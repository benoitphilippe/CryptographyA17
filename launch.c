#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
	char command[50]; 
	strcpy( command, "src/bin/python3.6 src/scr.py" );
	return system(command);
}
