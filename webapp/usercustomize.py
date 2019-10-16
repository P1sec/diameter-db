

# Hack: there are issues with Ubuntu's sitecustomize which will try
# to import the apport_python_hook module with Python 3.7 (https://bugs.launchpad.net/ubuntu/+source/apport/+bug/1774843)
# while repositories only include it for 3.6, triggering verbose
# error messages when exceptions happen, so let's override
# this behavior through the present usercustomize file

# We're importing "site" (so that we can import packages
# located in /usr/lib/python3.7/dist-packages for example)
# here, because we disabled loading it at startup through
# adding -S to the shebang, so that the apport hook is
# not imported at startup even when there is a syntax error
# in the script that would prevent the present hotfix
# to be loaded

import sys
import site
site.main()
sys.excepthook = sys.__excepthook__



