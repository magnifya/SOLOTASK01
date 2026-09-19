"""支持 python -m kms 调用。"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
