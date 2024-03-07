with open('config.ini', 'w') as configfile:
    with open('default_config.ini', "r") as default_config:
        default_settings = default_config.read()
        configfile.write(default_settings)