from configparser import ConfigParser

from sklearn import metrics
from sklearn.feature_extraction.text import CountVectorizer, TfidfTransformer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier

import training

import time

array_percentage = []
array_time_process = []

config = ConfigParser()
config.read('config.ini')
black_files = config['training']['black_files']
white_files = config['training']['white_files']


def get_feature_for_train(opws, opwf):
    ws_opcode_list = opws
    ws_count = len(ws_opcode_list)

    wf_opcode_list = opwf
    wf_count = len(wf_opcode_list)

    total = ws_count + wf_count
    labels = [1] * ws_count + [0] * wf_count
    corpus = ws_opcode_list + wf_opcode_list

    countvec = CountVectorizer(ngram_range=(2, 2), decode_error='ignore', max_features=15000, token_pattern=r'\b\w+\b'
                               , min_df=1, max_df=1.0)

    countvec_mat = countvec.fit_transform(corpus).toarray()

    transformer = TfidfTransformer(smooth_idf=False)
    tfidf_mat = transformer.fit_transform(countvec_mat).toarray()

    return tfidf_mat, labels


# Naive Bayes
def gnb_train(x, y):
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.15, random_state=1)
    start_gnb = time.time()
    gnb = GaussianNB()
    gnb.fit(x_train, y_train)
    stop_gnb = time.time() - start_gnb
    array_time_process.append(stop_gnb)
    y_pred = gnb.predict(x_test)

    array_percentage.append(metrics.accuracy_score(y_test, y_pred))
    print('naive bayes score: ')
    print(metrics.accuracy_score(y_test, y_pred))
    print('naive bayes confusion matrix: ')
    print(metrics.confusion_matrix(y_test, y_pred))
    print('naive bayes precision score:')
    print(metrics.precision_score(y_test, y_pred))
    print('naive bayes recall score:')
    print(metrics.recall_score(y_test, y_pred))
    print('naive bayes f1 score:')
    print(metrics.f1_score(y_test, y_pred))


# MLP of Deep Learning Algorithms
def mlp_train(x, y):
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.15, random_state=1)
    start_clf = time.time()
    clf = MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(5, 2), random_state=1)
    clf.fit(x_train, y_train)
    stop_clf = time.time() -start_clf
    array_time_process.append(stop_clf)
    y_pred = clf.predict(x_test)

    array_percentage.append(metrics.accuracy_score(y_test, y_pred))
    print('mlp score: ')
    print(metrics.accuracy_score(y_test, y_pred))
    print('mlp confusion matrix: ')
    print(metrics.confusion_matrix(y_test, y_pred))
    print('mlp precision score:')
    print(metrics.precision_score(y_test, y_pred))
    print('mlp recall score:')
    print(metrics.recall_score(y_test, y_pred))
    print('mlp f1 score:')
    print(metrics.f1_score(y_test, y_pred))


# Decision Tree
def ds_train(x, y):
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.15, random_state=1)
    ds = DecisionTreeClassifier()
    ds.fit(x_train, y_train)
    y_pred = ds.predict(x_test)
    print('ds score: ', metrics.accuracy_score(y_test, y_pred))


if __name__ == '__main__':
    print('loading black files...')
    black_code_list = training.get_all_opcode(black_files)
    black_code_list = [" ".join(x) for x in black_code_list]

    black_label = [1] * len(black_code_list)
    print('{0} black files loaded'.format(len(black_code_list)))

    print('loading white files...')
    white_code_list = training.get_all_opcode(white_files)
    white_code_list = [" ".join(x) for x in white_code_list]
    white_label = [0] * len(white_code_list)
    print('{0} white files loaded'.format(len(white_code_list)))

    x, y = get_feature_for_train(black_code_list, white_code_list)

    gnb_train(x, y)
    mlp_train(x, y)

    with open('time_accuracy.txt', 'w', encoding="utf-8") as fp:
        for x, y in zip(array_time_process, array_percentage):
            fp.write('{} {}\n'.format(x, y))
