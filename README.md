PE-Injection
============

A PE injection is a very powerfull injection technique. It allows you to inject code directly in other processes.   
It works by allocating the executable memory in the target process, relocate the image of the injector process, and then write the relocated image into target process. Finally the created remote thread will execute your code (it injects and executes your code).


The injector write his own image into another process, and a remote thread is created to execute the injected code.
