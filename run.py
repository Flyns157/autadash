import autadash

# =================================== Main ===================================
def main():
    autadash.init()
    autadash.app.run(debug=True, host='0.0.0.0', port=5000)

# =================================== Run ===================================
if __name__ == '__main__':
    main()