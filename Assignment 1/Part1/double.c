#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
	char last[100];
	strcpy(last, argv[argc-1]);
	double number = strtod(last, NULL);

	double result = number*2;

	char result_string[100];
	snprintf(result_string, sizeof(result_string), "%lf", result);

	strcpy(argv[argc-1], result_string);
	int pid = fork();
	if(pid == 0){
		if(argc <= 2){
			long long int ans = strtoll(argv[argc-1], NULL, 10);
			printf("%lld", ans);
		}else{
			char** argn = (char**)malloc((argc)*sizeof(char*));

			char modified_first[100];

			snprintf(modified_first, sizeof(modified_first), "./%s", argv[1]);
			argv[1] = modified_first;

			for(int i=1; i<argc; i++){
				argn[i-1] = argv[i];
			}
			argn[argc-1] = NULL;
			execvp(argv[1], argn);
		}
	}

	return 0;
}
