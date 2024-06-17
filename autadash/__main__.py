from __init__ import Server
from config import Config

app = Server(__name__)
app.config.from_object(Config)
app.run(debug=True)