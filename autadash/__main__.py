from autadash import Server
from autadash.config import Config

# Test
app = Server(__name__,
            static_url_path='',
            static_folder='assets',
            template_folder='templates')

app.run(debug=True)