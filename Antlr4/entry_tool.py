import csv

import subprocess
import concurrent
import json
# from config import *
from src.gpt import main_detection
# from src.contract_extractor import extract_function_with_contract
import logging
logging.basicConfig(level=logging.INFO)
if __name__=='__main__':
    main_detection()
