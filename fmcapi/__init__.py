"""
In a python package the __init__.py file is called whenever someone imports the package into their program.
"""

# Give credit where credit is due.
__author__ = 'Dax Mickelson <dmickels@cisco.com'
__credits__ = ['Ryan Malloy <rymalloy@cisco.com>', 'Neil Patel <neipatel@cisco.com>']
__maintainer__ = 'Dax Mickelson'
__email__ = 'dmickels@cisco.com'
__repository__ = 'https://github.com/daxm/Selfserve_FMC_usecase01'
__status__ = 'Development'

import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())

"""
When someone "imports *" from a package the __all__ list is what is imported.
Thanks to David Beazley's (Live and Let Die!) youtube video I'm configuring this variable to only
expose those functions and/or classes I want using the @export decorator.
"""
__all__ = []

# A decorator to add functions and/or classes to the __all__ list.
def export(defn):
    globals()[defn.__name__] = defn
    __all__.append(defn.__name__)
    return defn

from . import fmc
