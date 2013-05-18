###README###

Sample kernel extension for Mac OS X Mountain Lion that demonstrates how to hide
a process by modifying *allproc* and *pidhashtbl*. Necessary kernel symbols are
resolved during module initializiation.


Bugz/ToDo:

* process unhiding does not work (who needs unhiding anyway)
* support for more advanced hiding tricks?!

