import flask
import yara
import os
import time
import json
import logging
import hashlib
import atexit
from configparser import ConfigParser
from pathlib import Path
import tflearn
from numpy import argmax
from flask import Flask, request, redirect, render_template, url_for, abort, jsonify, json
from flask_restful import Resource, Api
from flask_cors import CORS

import training
from lib import Database

config = ConfigParser()
config.read('config.ini')

check_dir = config['training']['check_dir']

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = config['api']['upload_path']
app.config['MAX_CONTENT_LENGTH'] = int(config['api']['upload_max_length'])
cors = CORS(app, resources={r"/*": {"origins": "*"}})
api = Api(app)



class TempFile:

    def __init__(self, path, name):
        self.path = os.path.abspath(path)
        self.name = name

    def get_name(self):
        return self.name

    def get_path(self):
        return os.path.realpath(os.path.join(self.path, self.name))

    def __del__(self):
        # file = os.join(self.path, self.name)
        # if os.path.isfile(file):
        #     os.remove(self.file)
        pass


def vaild_file(filename):
    ALLOWED_EXTENSIONS = ['php']
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


def yarcat():
    if os.path.exists("./rules/output.yara") == True:
        os.remove("./rules/output.yara")
    with open("./rules/output.yara", "wb") as outfile:
        for root, dirs, files in os.walk("./rules", topdown=False):
            for name in files:
                fname = str(os.path.join(root, name))
                with open(fname, "rb") as infile:
                    if fname != './rules/output.txt':
                        outfile.write(infile.read())


def compileandscan(filematch):
    yarcat()

    rules = yara.compile('./rules/output.yara')
    matches = rules.match(filematch, timeout=60)
    ma = 0
    length = len(matches)
    if length > 0:
        c = matches
        dmatch = []
        for match in matches:
            dmatch.append(matches[ma].strings)
            ma = ma + 1

    else:
        matches = 'No YARA hits.'
        dmatch = None

    return [matches, dmatch]



def check_with_model(file_id):
    global model
    file = TempFile(os.path.join(app.config['UPLOAD_FOLDER']), file_id)
    ###
    file_opcodes = [training.get_file_opcode(file.get_path())]
    training.serialize_codes(file_opcodes)
    file_opcodes = tflearn.data_utils.pad_sequences(file_opcodes, maxlen=seq_length, value=0.)

    res_raw = model.predict(file_opcodes)
    res = {
        # revert from categorical
        'judge': True if argmax(res_raw, axis=1)[0] else False,
        'chance': float(res_raw[0][argmax(res_raw, axis=1)[0]]),
    }
    return res


dir = 'D://cnn-webshell-detect//check_dir'


class check_webshell(Resource):
    def get(self):
        yara_list = []
        shell_list = []
        file_list = []
        pred_label = []

        for root, dirs, filename in os.walk(dir):
            for subdir in dirs:
                os.path.join(root, subdir)
            for file in filename:
                f = os.path.join(root, file)
                if os.path.isfile(f) and vaild_file(f):
                    file_list.append(f)
                    pred_label.append(0)

                    res_check = check_with_model(f)
                    res = {
                        'file_name': f,
                        'malicious_judge': res_check['judge'],
                        'malicious_chance': res_check['chance'],
                    }

                    if res_check['judge']:
                        # res = res
                        # print(res)
                        shell_list.append(res)
                        pred_label = pred_label[:-1] + [1]

                        a = compileandscan(f)
                        stringtemp = ''
                        yara_array_string = []
                        if a[0] != 'No YARA hits.':
                            for i in a[0]:
                                stringtemp += ' '+str(i);
                            stringtemp = stringtemp.strip()
                            for i in a[1]:
                                small_yara_array_string = []
                                for j in i:
                                    get_string_from_tuple = ' '.join(str(v) for v in j)
                                    get_string_from_tuple = get_string_from_tuple.strip()
                                    small_yara_array_string.append(get_string_from_tuple)
                                yara_array_string.append(small_yara_array_string)
                            ur = {'filename': f, 'yararesults': stringtemp, 'yarastrings': yara_array_string}
                            yara_list.append(ur)

        return jsonify(
            shell_list=shell_list, yara_list=yara_list, file_list=file_list,
            len_shell_list=len(shell_list), len_yara_list=len(yara_list), len_file_list=len(file_list)
        )


class webshell_dashboard(Resource):
    def get(self):
        time_accuracy_arr = []
        overall_acuracy = []
        with open("time_accuracy.txt", "r", encoding="UTF-8") as ta:
            time_accuracy = ta.readlines()
            for i in time_accuracy:
                i = i.replace('\n', '').strip()
                i = i.split(' ')
                time_accuracy_arr.append(i)
        with open("time_accuracy_cnn.txt", "r", encoding="UTF-8") as ta:
            time_accuracy = ta.readlines()
            for i in time_accuracy:
                i = i.replace('\n', '').strip()
                i = i.split(' ')
                time_accuracy_arr.append(i)
        with open("overall_accuracy_cnn.txt", "r", encoding="UTF-8") as ta:
            cnn_overall_accuracy = ta.readlines()
            for i in cnn_overall_accuracy:
                i = i.replace('\n', '').strip()
                i = i.split(' ')
                overall_acuracy.append(i[-1])
        print(time_accuracy_arr)
        print(overall_acuracy)

        return jsonify(
            time_accuracy=time_accuracy_arr,
            overall_accuracy=overall_acuracy,
        )


api.add_resource(check_webshell, "/", "/check/upload")
api.add_resource(webshell_dashboard, "/dashboard")

if __name__ == '__main__':
    global model, seq_length

    host = config['server']['host']
    port = int(config['server']['port'])
    model_record = config['training']['model_record']
    seq_length = json.load(open(model_record, 'r'))['seq_length']
    #
    logging.info('loading model...')
    model = training.get_model()
    #
    logging.info('detection started')
    app.run(host='0.0.0.0', port=port, debug=True)