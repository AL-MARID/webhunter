import os
import sys
import json
import re
import time
import socket
import ssl
import sqlite3
import random
import threading
import queue
import concurrent.futures
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
from collections import defaultdict
import requests
from bs4 import BeautifulSoup
import dns.resolver
import whois
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.tree import Tree
import html
import xml.etree.ElementTree as ET

[Rest of the original code without comments]