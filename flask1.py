from flask import Flask, render_template, request, abort
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
import random
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'

class NameForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    submit = SubmitField('Submit')

RULES = [
    # SQL Injection
    re.compile(r"(\b(select|update|delete|insert)\b)", re.IGNORECASE),  #

    # XSS
    re.compile(r"(<\s*script\b)", re.IGNORECASE), #sCript

    # File Inclusion
    re.compile(r"(file:\s*///)", re.IGNORECASE),
]


ADVANCED_RULES = [
    # SQL Injection
    re.compile(r"(?:\b(select|update|delete|insert)\b|'[\s\S]*?('|\"|\`)|\b(like|=|--|#|;|=0|\|\||\%\d\d|@|@@)\b|AND\s(?:[01]|[tf]rue)|\bOR\b|[0-9]*\-|\*\d+|(?:\bGROUP\sBY\b|\bUNION\sSELECT\b|\bHAVING\b|\bWAITFOR\sDELAY\b|\bORDER\sBY\b)[\s\S]*?--\+?|[^\w\s\,]+|(?:[^\w\s])+[=]+(?:[^\w\s]))"),

    # XSS
    re.compile(r"(?i)(?=.*(?:prompt|alert|onload|onerror|onclick|onmouseover|onfocus|onblur|oninput|onkeydown|onkeypress|onkeyup|onmousedown|onmousemove|onmouseout|onmouseup|onpaste|onsubmit|onchange|oncontextmenu|ondrag|ondblclick|onactivate|onbeforeactivate|onbeforedeactivate|ondeactivate|onhelp|onstart|onfinish|onmouseenter|onmouseleave|ontouchstart|ontouchend|ontouchmove|ontouchcancel|onorientationchange|onpageshow|onresize|onscroll|onhashchange|eval)).*(?=.*(?:svg|script|image|img|audio|video|iframe|embed|object|form|select|a|abbr|base|link|math|brute|keygen|isindex|body|marquee|x|%|<\/|;|'|-|\/\/|>|<|\(|\)|,|&num;|&#[xX];|&#[0-9]+;|:|=|_)).*"),

    # RFI/LFI
    re.compile(r"(\.{2,}(/|\\|%5[Cc])(/?|\\\\)*)|(/?etc(/|\\|%5[Cc])((passwd|shadow|group|hosts|motd|issue|mysql/my\.cnf)|%00|/))|(php://(filter|expect)[^ ]*)|(http[^ ]*\.(txt|jpg|png))|(%(25)?2[efF])|(/[a-zA-Z0-9\-_]+){1,}/\d+/fd/\d+|(/proc(/(self|version|cmdline)|\d+/environ))|(/[a-zA-Z]+(\.php)?/)|(/[a-zA-Z0-9\-_]+/)*var(/[a-zA-Z0-9\-_]+)+/log(/(apache|apache2|nginx|httpd))?/(access|error)\.log")
]

def check_request(request_data):
    for rule in ADVANCED_RULES:
        if rule.search(request_data):
            return True
    return False

@app.route('/', methods=['GET', 'POST'])
def index():
    form = NameForm()
    response = ''
    if form.validate_on_submit():
        first_name = form.first_name.data
        last_name = form.last_name.data
        if check_request(first_name) or check_request(last_name):
            abort(403)
        
        greetings = ['Nice to meet you', 'Welcome', 'Hello']
        response = f"{random.choice(greetings)}, {first_name} {last_name}!"

    return render_template('index.html', form=form, response=response)

if __name__ == '__main__':
    app.run(port=5001)
