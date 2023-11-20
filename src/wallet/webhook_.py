from flask import Flask, request, abort

app = Flask('lol')


@app.route('/', methods=['POST'])
def get_webhook():
    if request.method == 'POST':
        print("received data: ", request.json)
        return 'success', 200
    else:
        abort(400)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=True)