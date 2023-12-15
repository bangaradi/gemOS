#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

int main(int argc, char* argv[])
{
	const char* path = argv[1];
	long long size = 0;

	struct stat st;
	if(stat(path, &st) == 0){
		if(S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)){
			long long total_size = 0;
			DIR *dir = NULL;
			if(S_ISDIR(st.st_mode)){
				total_size = st.st_size;
				dir = opendir(path);
			}else if(S_ISLNK(st.st_mode)){
				char buffer[1024];
				int f = readlink(path, buffer, 1024);
				dir = opendir(buffer);
				total_size = 0;
			}

			if (dir == NULL) {
				perror("unable to execute");
				return 0;
			}

			struct dirent* entry;
			while((entry = readdir(dir)) != NULL){
				if(strcmp(entry->d_name, ".")!=0 && strcmp(entry->d_name, "..")!=0){
					char child_path[1024];
					snprintf(child_path, sizeof(child_path), "%s/%s", path, entry->d_name);
					int fd[2];
					if(pipe(fd) == -1){
						perror("unable to execute");
						return 0;
					}

					pid_t pid = fork();

					if(pid == -1){
						perror("child");
						return 0;
					}
					if(pid == 0){
						dup2(fd[1], STDOUT_FILENO);
						close(fd[1]);
						close(fd[0]);
						execlp("./myDU", "./myDU", child_path, NULL);
						perror("exec error");
						exit(1);
					}else{
						close(fd[1]);
						dup2(fd[0], STDIN_FILENO);
						close(fd[0]);
						char buffer[1024];
						int nread;
						while((nread = read(STDIN_FILENO, buffer, sizeof(buffer))) > 0){
							write(STDIN_FILENO, buffer, nread);
						}
						char* endptr;
						long long int temp = strtoll(buffer, &endptr, 10);
						total_size += temp;

						wait(NULL);
					}

				}
			}
			closedir(dir);
			char str[50];
			sprintf(str, "%lld", total_size);
			printf("%s\n", str);
			exit(1);
		}else if(S_ISLNK(st.st_mode)){
			fprintf(stderr, "this is a link");
		}else{
			long long int file_size = st.st_size;
			char str[50];
			sprintf(str, "%lld", file_size);
			printf("%s\n", str);
			exit(1);
		}
	}else{
		perror("unable to execute");
	}
	return 0;
}
