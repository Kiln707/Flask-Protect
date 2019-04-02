from Flask import Flask

def create_app():
    app = Flask(__name__)
    #All other setup

    return app



if __name__ == '__main__':
    app = create_app()
