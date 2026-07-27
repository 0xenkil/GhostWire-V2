import utils.display as display
import sys
import os
sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            '..')))

sys.stdout.reconfigure(encoding='utf-8')

display.banner()
