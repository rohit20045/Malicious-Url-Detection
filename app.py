from flask import Flask,render_template,request
import joblib
import numpy as np
import re
from sklearn.model_selection import train_test_split
from urllib.parse import urlparse
from tld import get_tld

app=Flask(__name__)
@app.route("/")
@app.route('/home')
def home():
    return render_template("home.html")

@app.route('/result',methods=['POST','GET'])
def func():
    url=request.form['url_name']
    str_result=""   
    rf=joblib.load(r'D:\Project\malicious\model\model_url.sav')
    
    def having_ip_address(url):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
        if match:
            return 1
        else:    
            return 0
    
    def abnormal_url(url):
        hostname = urlparse(url).hostname
        hostname = str(hostname)
        match = re.search(hostname, url)
        if match:
            return 1
        else:
            return 0

    def count_dot(url):
        count_dot = url.count('.')
        return count_dot

    def count_www(url):
        url.count('www')
        return url.count('www')

    def count_atrate(url):
        return url.count('@')

    def no_of_dir(url):
        urldir = urlparse(url).path
        return urldir.count('/')

    def no_of_embed(url):
        urldir = urlparse(url).path
        return urldir.count('//')

    def shortening_service(url):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                        'tr\.im|link\.zip\.net',
                        url)
        if match:
            return 1
        else:
            return 0
        

    def count_https(url):
        return url.count('https')

    def count_http(url):
        return url.count('http')

    def count_per(url):
        return url.count('%')

    def count_ques(url):
        return url.count('?')

    def count_hyphen(url):
        return url.count('-')

    def count_equal(url):
        return url.count('=')

    #Length of URL
    def url_length(url):
        return len(str(url))


    #Hostname Length
    def hostname_length(url):
        return len(urlparse(url).netloc)

    def suspicious_words(url):
        match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',url)
        if match:
            return 1
        else:
            return 0

    def digit_count(url):
        digits = 0
        for i in url:
            if i.isnumeric():
                digits = digits + 1
        return digits

    def letter_count(url):
        letters = 0
        for i in url:
            if i.isalpha():
                letters = letters + 1
        return letters

    #First Directory Length
    def fd_length(url):
        urlpath= urlparse(url).path
        try:
            return len(urlpath.split('/')[1])
        except:
            return 0

    #Length of Top Level Domain

    def tld_length(tld):
        try:
            return len(tld)
        except:
            return -1

    import numpy as np
    def make_feature(url):
        status = []
        status.append(having_ip_address(url))
        status.append(abnormal_url(url))
        status.append(count_dot(url))
        status.append(count_www(url))
        status.append(count_atrate(url))
        status.append(no_of_dir(url))
        status.append(no_of_embed(url))
        
        status.append(shortening_service(url))
        status.append(count_https(url))
        status.append(count_http(url))
        
        status.append(count_per(url))
        status.append(count_ques(url))
        status.append(count_hyphen(url))
        status.append(count_equal(url))
        
        status.append(url_length(url))
        status.append(hostname_length(url))
        status.append(suspicious_words(url))
        status.append(digit_count(url))
        status.append(letter_count(url))
        status.append(fd_length(url))
        tld = get_tld(url,fail_silently=True)
        status.append(tld_length(tld))
        return status

    def get_prediction_from_url(test_url):

        features_test = make_feature(test_url)
        features_test = np.array(features_test).reshape((1, -1))
        pred = rf.predict(features_test)
        flag = int (pred[0])
        
        if flag == 0:
            str_res="SAFE"
        elif flag == 1:
            str_res="DEFACEMENT"
        elif flag == 2:
            str_res="MALWARE"
        elif flag == 3:
            str_res="PHISHING"
        return str_res
         
    str_result=get_prediction_from_url(url)
    return ({ 'The site is ' : str_result})


app.run(debug=True, port=3000)
