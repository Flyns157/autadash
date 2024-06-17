from __init__ import Server
from config import Config

# Test
app = Server(__name__,
            static_url_path='',
            static_folder='assets',
            template_folder='templates')
app.config.from_object(Config)
app.run(debug=True)