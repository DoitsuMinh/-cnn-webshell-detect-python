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

# logging.basicConfig(
#     level=logging.DEBUG, filename='demo.log', filemode='w',
#     format='%(asctime)s %(filename)s [line:%(lineno)d] %(levelname)s %(message)s'
# )


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


@app.route('/check/upload')
def check_webshell():
    yara_list = []
    shell_list = []
    file_list = []
    pred_label = []
    result_list = []

    for root, dirs, filename in os.walk(dir):
        for subdir in dirs:
            os.path.join(root, subdir)
        for file in filename:
            f = os.path.join(root, file)
            if os.path.isfile(f) and vaild_file(f):
                file_list.append(f)
                pred_label.append(0)
                # a = compileandscan(f)
                # ur = {'filename': f, 'yararesults': a[0], 'yarastrings': a[1]}
                # if a[0] != 'No YARA hits.':
                #     ur = ur
                #     print(ur)
                #     yara_list.append(ur)

                res_check = check_with_model(f)
                res = {
                    'file_name': f,
                    'malicious_judge': res_check['judge'],
                    'malicious_chance': res_check['chance'],
                }

                if res_check['judge']:
                    res = res
                    result_list.append(res)
                    # print(res)
                    shell_list.append(res)
                    pred_label = pred_label[:-1] + [1]

                    a = compileandscan(f)
                    ur = {'filename': f, 'yararesults': a[0], 'yarastrings': a[1]}
                    print(ur)
                    if a[0] != 'No YARA hits.':
                        yara_list.append(ur)

                # print(res)
                # if a[0] != 'No YARA hits.' or res_check['judge']:
                #     result = {
                #         'file name': f,
                #         'malicious judge': res_check['judge'],
                #         'malicious chance': res_check['chance'],
                #         'yararesults': a[0],
                #         'yarastrings': a[1]
                #     }

                    # result_list.append(result)
    print(result_list)
    print('Total file php: ', len(file_list))
    print('Total yara: ', len(yara_list))
    print('Total CNN: ', len(shell_list))
    print(pred_label)
    # print(len(pred_label))
    # print('Total webshell predict: ', len(result_list))

    # return jsonify(result_list: result_list,
    # total_file_php: len(file_list),
    # total_yara: len(yara_list), total_cnn: len(shell_list))
# abc = res.result_list

@app.route('/')
def index():
    return redirect(url_for('check_webshell'))


@atexit.register
def atexit():
    logging.info('detection stopped')


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
    check_webshell()
