#include<fcntl.h>
#include<unistd.h>
#include<stdio.h>

void read_syscall_binary(char* filename, char* buffer);
void print_str(char* string);
int str_icpy(char* string1, int offset1, char* string2, int offset2);
int get_dump_offset(char* string);
void read_syscall_instructions(char* syscalls, int fd);
int find_marker(int fd);

int main(int argc, char* argv[]) {
   char syscalls[100000] = {'\0'};
   //char target_syscalls[100000] = {'\0'};

   read_syscall_binary("log", syscalls);

   print_str(syscalls);

   return 0;
}

void read_syscall_binary(char* filename, char* buffer) {
   
   int fd = open(filename, O_RDONLY);
   if (fd < 0) printf("File not found!");

   int offset = find_marker(fd);
   close(fd);
   fd = open(filename, O_RDONLY);
   
   int ret_offset = lseek(fd, offset, SEEK_SET);

   read_syscall_instructions(buffer, fd);
}

void print_str(char* string) {
   int i = 0;
   for (i = 0; string[i] != '\0'; i++) printf("%c", string[i]);
}

int get_dump_offset(char* string) {
   int i = 0; 
   int spaces = 0;
   for (i = 0; string[i] != '\0'; i++) {
      if (string[i] == ' ') spaces++;
      if (spaces == 5) return i+1;
   }
   return -1;
}

int str_icpy(char* string1, int offset1, char* string2, int offset2) {
   for (; string2[offset2] != '\0';offset1++, offset2++) {
      string1[offset1] = string2[offset2];
   }

   return offset1;
}

void read_syscall_instructions(char* syscalls, int fd) {
   char instructions[1000] = {'\0'}; 
   char line[10000] = {'\0'};
   int line_offset = 0;
   int readsize = 0;
   int offset = 0;
   int flag = 0;

   while (1) {

      line_offset = 0;
      while (1) { 
         readsize = read(fd, instructions, 1);
         if (readsize <= 0) break;
         if (instructions[0] == '\n') break;

         line[line_offset] = instructions[0]; 
         line_offset++;
      }

      if (readsize <= 0) break;
      line[line_offset] = '\0';

      int sys_dump_offset = 0;
      flag = 1;
      
      if (flag > 0) get_dump_offset(line);

      offset = str_icpy(syscalls, offset, line, sys_dump_offset);
   }

}

int find_marker(int fd) {

   char instructions[1000] = {'\0'}; 
   int flag = 0;
   int stars = 0;
   int offset = 0;
   int i = 0;

   while (read(fd, instructions, 999) > 0 && flag == 0) {

       for (i=0; i < 1000 && instructions[i] != '\0'; i++) {
          offset += 1;
          if (instructions[i] == '*' && stars > 2) {
             stars = 1;
          } else if (instructions[i] == '^' && stars == 2) {
             flag = 1;
             break;
          } else if (instructions[i] == '*') {
             stars += 1;
          } else {
             stars = 0;
          }
       }
   }

   return offset;
}
