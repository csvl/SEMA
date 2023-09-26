STYLE_CLASSIC = {
    'COLOR_SCHEME': {
        'EDGECOLOR_CONDITIONAL_TRUE'  : {'color': 'green'},
        'EDGECOLOR_CONDITIONAL_FALSE' : {'color': 'red'},
        'EDGECOLOR_UNCONDITIONAL'     : {'color': 'blue'},
        'EDGECOLOR_NEXT'              : {'color': 'blue', 'style': 'dashed'},
        'EDGECOLOR_CALL'              : {'color': 'black'},
        'EDGECOLOR_RET'               : {'color': 'gray'},
        'EDGECOLOR_FAKE_RET'          : {'color': 'gray', 'style' :'dotted'},
        'EDGECOLOR_UNKNOWN'           : {'color': 'orange'}
    }
}

STYLE_THICK = {
    'COLOR_SCHEME': {
        'EDGECOLOR_CONDITIONAL_TRUE'  : {'color': 'green', 'width': '2'},
        'EDGECOLOR_CONDITIONAL_FALSE' : {'color': 'red', 'width': '2'},
        'EDGECOLOR_UNCONDITIONAL'     : {'color': 'blue', 'width': '2'},
        'EDGECOLOR_NEXT'              : {'color': 'blue', 'style': 'dashed', 'width': '2'},
        'EDGECOLOR_CALL'              : {'color': 'black', 'width': '2'},
        'EDGECOLOR_RET'               : {'color': 'gray', 'width': '2'},
        'EDGECOLOR_FAKE_RET'          : {'color': 'gray', 'style' :'dashed', 'width': '2'},
        'EDGECOLOR_UNKNOWN'           : {'color': 'orange', 'width': '2'}
    }
}

STYLE_BLACK = {
    'COLOR_SCHEME': {
        'EDGECOLOR_CONDITIONAL_TRUE'  : {'color': 'black'},
        'EDGECOLOR_CONDITIONAL_FALSE' : {'color': 'black'},
        'EDGECOLOR_UNCONDITIONAL'     : {'color': 'black'},
        'EDGECOLOR_NEXT'              : {'color': 'black', "style":"dashed"},
        'EDGECOLOR_CALL'              : {'color': 'gray'},
        'EDGECOLOR_RET'               : {'color': 'gray'},
        'EDGECOLOR_FAKE_RET'          : {'color': 'gray', 'style' :'dashed'},
        'EDGECOLOR_UNKNOWN'           : {'color': 'orange'}
    }
}

STYLE_DARK = {
    'COLOR_SCHEME': {
        'EDGECOLOR_CONDITIONAL_TRUE'  : {'color': '#006400'},
        'EDGECOLOR_CONDITIONAL_FALSE' : {'color': '#8b0000'},
        'EDGECOLOR_UNCONDITIONAL'     : {'color': '#00008b'},
        'EDGECOLOR_NEXT'              : {'color': '#00008b', 'style': 'dashed'},
        'EDGECOLOR_CALL'              : {'color': 'black'},
        'EDGECOLOR_RET'               : {'color': '#a9a9a9'},
        'EDGECOLOR_FAKE_RET'          : {'color': '#a9a9a9', 'style' :'dotted'},
        'EDGECOLOR_UNKNOWN'           : {'color': '#ff8c00'}
    }
}

STYLE_LIGHT = {
    'COLOR_SCHEME': {
        'EDGECOLOR_CONDITIONAL_TRUE'  : {'color': '#ADFF2F'},
        'EDGECOLOR_CONDITIONAL_FALSE' : {'color': '#F08080'},
        'EDGECOLOR_UNCONDITIONAL'     : {'color': '#87CEFA'},
        'EDGECOLOR_NEXT'              : {'color': '#87CEFA', 'style': 'dashed'},
        'EDGECOLOR_CALL'              : {'color': '#202020'},
        'EDGECOLOR_RET'               : {'color': '#C0C0C0'},
        'EDGECOLOR_FAKE_RET'          : {'color': '#C0C0C0', 'style' :'dotted'},
        'EDGECOLOR_UNKNOWN'           : {'color': '#FFD700'}
    }
}

STYLE_KYLE = {
    'COLOR_SCHEME': {
        'EDGECOLOR_CONDITIONAL_TRUE'  : {'color': 'green'},
        'EDGECOLOR_CONDITIONAL_FALSE' : {'color': 'red'},
        'EDGECOLOR_UNCONDITIONAL'     : {'color': 'blue'},
        'EDGECOLOR_NEXT'              : {'color': 'blue', 'style': 'dashed'},
        'EDGECOLOR_CALL'              : {'color': 'black'},
        'EDGECOLOR_RET'               : {'color': 'purple'},
        'EDGECOLOR_FAKE_RET'          : {'color': 'purple', 'style' :'dotted'},
        'EDGECOLOR_UNKNOWN'           : {'color': 'yellow'}
    }
}

class Style:
    def __init__(self, st):
        self.style = st
        
    def make_edge(self, edge, edge_type):
        edge_attrs = self.style['COLOR_SCHEME']['EDGECOLOR_' + edge_type.upper()]
        for k,v in edge_attrs.items():
            setattr(edge, k, '"'+v+'"')

_style = Style(STYLE_CLASSIC)

def set_style(c):
    global _style
    if type(c) is str:
        if c == 'classic':
            set_style(STYLE_CLASSIC)
        elif c == 'thick':
            set_style(STYLE_THICK)
        elif c == 'black':
            set_style(STYLE_BLACK)
        elif c == 'dark':
            set_style(STYLE_DARK)
        elif c == 'light':
            set_style(STYLE_LIGHT)
        elif c == 'kyle':
            set_style(STYLE_KYLE)
        else:
            raise KeyError("Style '%s' not defined" % c)
    else:
        _style = Style(c)

def get_style():
    return _style
