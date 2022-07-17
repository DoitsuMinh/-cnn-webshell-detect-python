#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from functools import reduce
from configparser import ConfigParser

import tflearn
from numpy import argmax
from sklearn import model_selection, metrics

import training

import time

array_percentage = []
array_time_process = []

config = ConfigParser()
config.read('config.ini')
black_files = config['training']['black_files']
white_files = config['training']['white_files']
model_record = config['training']['model_record']
check_dir = config['training']['check_dir']


def test_model(x1_code, y1_label, x2_code, y2_label):
    global model_record

    x1_code.extend(x2_code)
    y1_label.extend(y2_label)

    print('serializing opcodes')
    training.serialize_codes(x1_code)

    x_train, x_test, y_train, y_test = model_selection.train_test_split(x1_code, y1_label, test_size=0.15, shuffle=True)
    print('trainning set size: {0}'.format(len(x_train)))
    print('testing set size: {0}'.format(len(x_test)))

    record = json.load(open(model_record, 'r'))

    seq_length = len(reduce(lambda x, y: x if len(x) > len(y) else y, x1_code))
    optimizer = record['optimizer']
    learning_rate = record['learning_rate']
    loss = record['loss']
    n_epoch = record['n_epoch']
    batch_size = record['batch_size']

    x_train = tflearn.data_utils.pad_sequences(x_train, maxlen=seq_length, value=0.)
    x_test = tflearn.data_utils.pad_sequences(x_test, maxlen=seq_length, value=0.)

    y_train = tflearn.data_utils.to_categorical(y_train, nb_classes=2)

    start_cnn = time.time()
    network = training.create_network(
        seq_length,
        optimizer=optimizer,
        learning_rate=learning_rate,
        loss=loss
    )
    model = tflearn.DNN(network, tensorboard_verbose=0)
    model.fit(
        x_train, y_train,
        n_epoch=n_epoch,
        shuffle=True,
        validation_set=0.1,
        show_metric=True,
        batch_size=batch_size,
        run_id='webshell')
    stop_cnn = time.time()-start_cnn

    y_pred = model.predict(x_test)
    y_pred = argmax(y_pred, axis=1)

    # y_pred = model.predict(x_test_final)
    # y_pred = argmax(y_pred, axis=1)

    cnn_accuracy = metrics.accuracy_score(y_test, y_pred)

    array_time_process.append(stop_cnn)
    array_percentage.append(cnn_accuracy)

    print('metrics.accuracy_score:')
    print(metrics.accuracy_score(y_test, y_pred))
    print('metrics.confusion_matrix:')
    print(metrics.confusion_matrix(y_test, y_pred))
    print('metrics.precision_score:')
    print(metrics.precision_score(y_test, y_pred))
    print('metrics.recall_score:')
    print(metrics.recall_score(y_test, y_pred))
    print('metrics.f1_score:')
    print(metrics.f1_score(y_test, y_pred))

    cm = metrics.confusion_matrix(y_test, y_pred)
    TP = cm[0][0]
    FN = cm[0][1]
    FP = cm[1][0]
    TN = cm[1][1]

    # Sensitivity, hit rate, recall, or true positive rate
    TPR = TP / (TP + FN)
    # Specificity or true negative rate
    TNR = TN / (TN + FP)
    # Precision or positive predictive value
    PPV = TP / (TP + FP)
    # Negative predictive value
    NPV = TN / (TN + FN)
    # Fall out or false positive rate
    FPR = FP / (FP + TN)
    # False negative rate
    FNR = FN / (TP + FN)
    # False discovery rate
    FDR = FP / (TP + FP)

    # Overall accuracy
    ACC = (TP + TN) / (TP + FP + FN + TN)
    print('True Positive Rate = ',TPR)
    print('True Negative Rate = ', TNR)
    print('Precision = ',PPV)
    print('Negative Predict value = ',NPV)
    print('False Positive Rate = ',FPR)
    print('False Negative Rate = ',FNR)
    print('False Discovery = ',FDR)

    array_overall_accuracy = [TPR, TNR, PPV, NPV, FPR, FNR, FDR]
    array_overall_accuracy_name = ['True Positive Rate', 'True Negative Rate', 'Precision', 'Negative Predict value',
                                   'False Positive Rate', 'False Negative Rate', 'False Discovery']
    # print('metrics.accuracy_score:')
    # print(metrics.accuracy_score(y_test_label, y_pred))
    # print('metrics.confusion_matrix:')
    # print(metrics.confusion_matrix(y_test_label, y_pred))
    # print('metrics.precision_score:')
    # print(metrics.precision_score(y_test_label, y_pred))
    # print('metrics.recall_score:')
    # print(metrics.recall_score(y_test_label, y_pred))
    # print('metrics.f1_score:')
    # print(metrics.f1_score(y_test_label, y_pred))
    with open('time_accuracy_cnn.txt', 'w', encoding="utf-8") as fp:
        for x, y in zip(array_time_process, array_percentage):
            fp.write('{} {}\n'.format(x, y))

    with open('overall_accuracy_cnn.txt', 'w', encoding="utf-8") as fp:
        for x, y in zip(array_overall_accuracy_name, array_overall_accuracy):
            fp.write('{} {}\n'.format(x, y))


if __name__ == '__main__':
    print('loading black files...')
    black_code_list = training.get_all_opcode(black_files)
    black_label = [1] * len(black_code_list)
    print('{0} black files loaded'.format(len(black_code_list)))

    print('loading white files...')
    white_code_list = training.get_all_opcode(white_files)
    white_label = [0] * len(white_code_list)
    print('{0} white files loaded'.format(len(white_code_list)))

    #  all
    test_model(black_code_list, black_label, white_code_list, white_label)
