#generated using palettable
PALETTES = {
 'grays'  : ['#FFFFFD', '#D6D6D4', '#B1B1B0', '#908F8F', '#727171', '#545453', '#373737', '#1A1919', '#000000'], 
 'greens' : ['#F7FCF5', '#E5F5E0', '#C7E9C0', '#A1D99B', '#74C476', '#41AB5D', '#238B45', '#006D2C', '#00441B'], 
 'purples': ['#FCFBFD', '#EFEDF5', '#DADAEB', '#BCBDDC', '#9E9AC8', '#807DBA', '#6A51A3', '#54278F', '#3F007D'], 
 'blues'  : ['#F7FBFF', '#DEEBF7', '#C6DBEF', '#9ECAE1', '#6BAED6', '#4292C6', '#2171B5', '#08519C', '#08306B'],
 'reds'   : ['#FFF5F0', '#FEE0D2', '#FCBBA1', '#FC9272', '#FB6A4A', '#EF3B2C', '#CB181D', '#A50F15', '#67000D']
}

try:
    from palettable.colorbrewer.sequential import *
    from palettable.cmocean.sequential import *

    PALETTES.update({
	'greens' : Greens_9.hex_colors,
	'blues'  : Blues_9.hex_colors,
	'purples': Purples_9.hex_colors,
	'reds'   : Reds_9.hex_colors,
	'grays'  : Gray_9_r.hex_colors,
	'algae'  : Algae_8.hex_colors,
	'solar'  : Solar_9_r.hex_colors
    })
except:
    pass

def get_palette(name):
    return PALETTES[name]
    
def get_palette_names():
    return PALETTES.keys()
