# CNN Webshell Detection

An PHP webshell detection system using CNN and Yara Rules

## Installation note

Dependencies

```
pip install -r requirements.txt
```

Initialize dataset，black(webshell) and white(non-webshell) samples are located in the `dataset/{black,white}` directory：

```
git submodule init
git submodule update
```
Note: This system using only 2137 samples

Initialize the database (for running the web UI)

```
mysql -u<username> -p<password> < schema.sql
```
For xampp: input schema.sql to phpmyadmin

## Instruction for use

Train a new model：

```
./training.py
```

Run Demo（default port `0.0.0.0:5000`）：

```
./demo.py
```

Train a new model, and test it：

```
./test_model_metric_new.py
```


## Link

1. [Design and Implementation of Webshell Detection Platform Based on CNN](https://www.grassfish.net/2017/11/18/cnn-webshell-detect/)
2. [Toward a Deep Learning Approach for Detecting PHP Webshell](https://repository.vnu.edu.vn/bitstream/VNU_123/138340/1/2019_KY_Toward_a_Deep_Learning.pdf)
