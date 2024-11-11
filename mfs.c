#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <ctype.h>

#define WHITESPACE " \t\n"
#define MAX_COMMAND_SIZE 255    // The maximum command-line size
#define MAX_NUM_ARGUMENTS 32 

//char error_message[30] = "An error has occurred\n";

struct __attribute__((__packed__)) DirectoryEntry {
  char      DIR_Name[11];
  uint8_t   DIR_Attr;
  uint8_t   Unused1[8];
  uint16_t  DIR_FirstClusterHigh;
  uint8_t   Unused2[4];
  uint16_t  DIR_FirstClusterLow;
  uint32_t  DIR_FileSize;
};

struct DirectoryEntry dir[16];

/* Boot and BPB Sector (SECTOR 0) */
char     BS_OEMName[8];
int16_t  BPB_BytesPerSec;
int8_t   BPB_SecPerClus;
int16_t  BPB_RsvdSecCnt;
int8_t   BPB_NumFATs;
int16_t  BPB_RootEntCnt;
char     BS_VolLab[11];
int32_t  BPB_FATSz32;
int32_t  BPB_RootClus; // Store sector number of the first cluster of root directory
int16_t  BPB_ExtFlags;
int16_t  BPB_FSInfo;

//RootDirSectors = ((BPB_RootEntCnt * 32) + (BPB_BytsPerSec – 1)) / BPB_BytsPerSec;
int32_t  RootDirSectors = 0; 
int32_t  FirstDataSector = 0;
int32_t  FirstSectorofCluster = 0;

FILE* fp;

/* DECLARATION OF FUNCTIONS */
void openfile(char* token[]);
void closefile();
void info();
void stat(char* token[]);
void get(char* token[]);
int put(char* token[]);
void ls();
void del(char* token[]);
void undel(char* name);
int LBAToOffset(int32_t sector);
int16_t NextLB(uint32_t sector);
void FiletoDirName(char** filename);
void update_directory(char* name, uint32_t cluster, uint32_t filesize);
void DirtoFileName(char* dirname, char* filename);

void tokenizing_process(char* command_string, char* token[]) {
  int token_count = 0;                                                                            
  //Pointer to point to the token
  //parsed by strsep
  char* argument_pointer;                                         
                                                           
  char* working_string  = strdup(command_string);                

  //we are going to move the working_string pointer so
  //keep track of its original value so we can deallocate
  //the correct amount at the end
    
  char* head_ptr = working_string;
    
  //Tokenize the input with whitespace used as the delimiter
  while (((argument_pointer = strsep(&working_string, WHITESPACE )) != NULL) &&
              (token_count<MAX_NUM_ARGUMENTS)) {
    // Only add non-empty tokens
    if (strlen(argument_pointer) != 0) {
      token[token_count] = strndup(argument_pointer, MAX_COMMAND_SIZE);
      token_count++;
    }
  }
  token[token_count] = NULL;  //Add NULL at the end of array
  free(head_ptr);
}

int main( int argc, char * argv[] )
{
  char * command_string = (char*) malloc( MAX_COMMAND_SIZE );
  while (1) {
    printf("msh> ");
    while(!fgets(command_string, MAX_COMMAND_SIZE, stdin));
    char *token[MAX_NUM_ARGUMENTS];
    tokenizing_process(command_string, token);

    // When user does not input anything, keep looping
    if (token[0] == NULL) {
      continue;
    }

    // Exit the shell
    if ((strcmp(token[0], "exit") == 0) || (strcmp(token[0], "quit") == 0)) {
      break;
    }

    // Open file command
    if (strcmp(token[0], "open") == 0) {
      openfile(token);
      continue;
    }

    // Close file command
    if (strcmp(token[0], "close") == 0) {
      closefile();
      continue;
    }

    // Show info of fat32 file
    if (strcmp(token[0], "info") == 0) {
      info();
      continue;
    }

    // Show stat of input file
    if (strcmp(token[0], "stat") == 0) {
      stat(token);
      continue;
    }

    // Changing directory
    if (strcmp(token[0], "cd") == 0) {
      if (token[1] == NULL) {
        printf("Error: Must provide a directory\n");
      }
      else {
        if (chdir(token[1]) != 0) {
          printf("Error: Cannot change directory\n");
        }
      }
      continue;
    }

    // Get the filename
    if (strcmp(token[0], "get") == 0) {
      get(token);
      continue;
    }

    // Put new file into fat32 file
    if (strcmp(token[0], "put") == 0) {
      put(token);
      continue;
    }

    // List all the file
    if (strcmp(token[0], "ls") == 0) {
      ls();
      continue;
    }

    // Delete the file
    if (strcmp(token[0], "del") == 0) {
      del(token);
      continue;
    }

    // Undelete the file
    if (strcmp(token[0], "undel") == 0) {
      undel(token[1]);
      continue;
    }

  }


  return 0;
}

void openfile(char* token[]) {
  if (token[1] == NULL) {
    printf("Error: File system image not found.\n");
    return;
  }
  if (fp != NULL) {
    printf("Error: File system image already open.\n");
    return;
  }
  fp = fopen(token[1], "r");
  // Check if file is opened successfully or not
  if (fp == NULL) {
    printf("Error: the file cannot be opened\n");
    return;
  }
  /*                          Offset  Size
  char     BS_OEMName[8];       3       8
  int16_t  BPB_BytesPerSec;     11      2      
  int8_t   BPB_SecPerClus;      13      1
  int16_t  BPB_RsvdSecCnt;      14      2
  int8_t   BPB_NumFATs;         16      1
  int16_t  BPB_RootEntCnt;      17      2
  int32_t  BPB_FATSz32;         36      4
  int16_t  BPB_ExtFlags;        40      2
  int32_t  BPB_RootClus;        44      4
  int16_t  BPB_FSInfo;          48      2
  char     BS_VolLab[11];       71      11
  */
  fseek(fp, 3, SEEK_SET);            // Move to 3rd byte to read BS_jmpBoot
  fread(&BS_OEMName, 8, 1, fp);      // Read 8 bytes of BS_OEMName next
  fread(&BPB_BytesPerSec, 2, 1, fp); // Read 2 bytes of BS_BytesPerSec next
  fread(&BPB_SecPerClus, 1, 1, fp);  // Read 1 byte of BS_SecPerClus next
  fread(&BPB_RsvdSecCnt, 2, 1, fp);  // Read 2 bytes of BS_RsvdSecCnt next
  fread(&BPB_NumFATs, 1, 1, fp);     // Read 1 byte next
  fread(&BPB_RootEntCnt, 2, 1, fp);  // Read 2 bytes next
  fseek(fp, 36, SEEK_SET);           // Move to 36th byte to read BPB_FATSz32
  fread(&BPB_FATSz32, 4, 1, fp);     // Read 4 bytes of BPB_FATSz32
  fread(&BPB_ExtFlags, 2, 1, fp);
  fseek(fp, 44, SEEK_SET);           // Move to 44th byte to read BPB_RootClus
  fread(&BPB_RootClus, 4, 1, fp);    // Read 4 bytes
  fread(&BPB_FSInfo, 2, 1, fp);
  fseek(fp, 71, SEEK_SET);           // Move to 71th byte to read BS_VolLab
  fread(&BS_VolLab, 11, 1, fp);

  RootDirSectors = LBAToOffset(BPB_RootClus);
  //printf("%d\n", FirstClusterAddr);
  fseek(fp, RootDirSectors, SEEK_SET);
  // Read 16 entries to DirectoryEntry struct
  for (int i = 0; i < 16; i++) {
    fread(&dir[i], 32, 1, fp);
  }
}

void closefile() {
  if (fp == NULL) {
    printf("Error: File system not open.\n");
    return;
  }
  fclose(fp);
  fp = NULL; // Set fp back to NULL to indicate no file is currently opened
}

void info() {
  if (fp == NULL) {
    printf("Error: File system image must be opened first.\n");
    return;
  }
  printf("                  hexadecimal     base 10\n");
  printf("BPB_BytesPerSec      %#-14x %d\n", BPB_BytesPerSec, BPB_BytesPerSec);
  printf("BPB_SecPerClus       %#-14x %d\n", BPB_SecPerClus, BPB_SecPerClus);
  printf("BPB_RsvdSecCnt       %#-14x %d\n", BPB_RsvdSecCnt, BPB_RsvdSecCnt);
  printf("BPB_NumFATs          %#-14x %d\n", BPB_NumFATs, BPB_NumFATs);
  printf("BPB_FATSz32          %#-14x %d\n", BPB_FATSz32, BPB_FATSz32);
  printf("BPB_ExtFlags         %#-14x %d\n", BPB_ExtFlags, BPB_ExtFlags);
  printf("BPB_RootClus         %#-14x %d\n", BPB_RootClus, BPB_RootClus);
  printf("BPB_FSInfo           %#-14x %d\n", BPB_FSInfo, BPB_FSInfo);
}

void stat(char* token[]) {
  // Check if file is currently open
  if (fp == NULL) {
    printf("Error: File system image must be opened first.\n");
    return;
  }
  // Check if we have any input file
  if (token[1] == NULL) {
    printf("Error: File not found.\n");
    return;
  }
  //char* formatname = token[1];
  FiletoDirName(&token[1]); // Reformat the input file name
  printf("Formatname: %s\n", token[1]);
  for (int i = 0; i < 16; i++) {
    if (strncmp(token[1], dir[i].DIR_Name, 11) == 0) {
      printf("Attr: %d\n", dir[i].DIR_Attr);
      printf("First Cluster High: %d\n", dir[i].DIR_FirstClusterHigh);
      printf("First Cluster Low: %d\n", dir[i].DIR_FirstClusterLow);
      printf("File Size: %d\n", dir[i].DIR_FileSize);
    }
  }
}

void get(char* token[]) {
  // Checkif file is currently open
  if (fp == NULL) {
    printf("Error: File system image must be opened first.\n");
    return;
  }
  // Checkfor input file
  if (token[1] == NULL) {
    printf("Error: Need the filename.\n");
    return;
  }
  else {
    char* filename = (char*)malloc(sizeof(char));
    // If we want to paste into new file name
    if (token[2] != NULL) {
      strncpy(filename, token[2], strlen(token[2]));
    }
    else { // If we want to keep the current file name
      strncpy(filename, token[1], strlen(token[1]));
    }
    // Pointer that point to the file name string
    char* dirstr = (char*)malloc(strlen(token[1]));
    strncpy(dirstr, token[1], strlen(token[1]));
    FiletoDirName(&dirstr); // Change the format of file name
    for (int i = 0; i < 16; i++) {
      if (strncmp(dirstr, dir[i].DIR_Name, 11) == 0) {
        int FileClusterNum = (dir[i].DIR_FirstClusterHigh << 16) | dir[i].DIR_FirstClusterLow;
        int FileAddr = LBAToOffset(FileClusterNum);
        FILE* fptr = fopen(filename, "w");
        if (!fptr) {
          printf("Error: File cannot be opened.\n");
          return;
        }
        fseek(fp, FileAddr, SEEK_SET);
        char* ptr = malloc(dir[i].DIR_FileSize);
        fread(ptr, dir[i].DIR_FileSize, 1, fp);
        fwrite(ptr, dir[i].DIR_FileSize, 1, fptr);
        fclose(fptr);
        return;
      }
    }
    printf("Error: File not found.\n");
    return;
  }
}

int put(char* token[]) {
  if (fp == NULL) {
    printf("Error: File system image must be opened first.\n");
    return -1;
  }
  if (token[1] == NULL) {
    printf("Error: Need the filename.\n");
    return -1;
  }
  else {
    FILE* file_to_copy = fopen(token[1], "rb");
    if (!file_to_copy) {
      printf("Error: Cannot retrieve file.\n");
      return -1;
    }
    uint32_t Cluster = BPB_RootClus; // Holds the current cluster number
    int16_t NextCluster; // To find the next free block of data
    while (1) {
      NextCluster = NextLB(Cluster);
      if (NextCluster == 0x00) {
        break;
      }
      Cluster++;
    }
    //fseek(file_to_copy, 0, SEEK_END);
    int Bytes_to_copy = ftell(file_to_copy);
    fseek(file_to_copy, 0, SEEK_SET);
    int FileAddr = LBAToOffset(Cluster);

    char* ptr = malloc(Bytes_to_copy); // Pointer that points to the array of data
    while (Bytes_to_copy > BPB_BytesPerSec) {
      fseek(fp, FileAddr, SEEK_SET);
      fread(ptr, 512, 1, file_to_copy);
      fwrite(ptr, 512, 1, fp);
      Cluster++;
      NextCluster = NextLB(Cluster);
      if (NextCluster != 0x00) {
        printf("Error: No free space available.\n");
        fclose(file_to_copy);
        return -1;
      }
      Bytes_to_copy -= BPB_BytesPerSec;
    }
    if (Bytes_to_copy > 0) {
      FileAddr = LBAToOffset(Cluster);
      fseek(fp, FileAddr, SEEK_SET);
      fread(ptr, 1, Bytes_to_copy, file_to_copy);
      fwrite(ptr, 1, Bytes_to_copy, fp);
    }
    char dirstr[11];
    strncpy(dirstr, token[1], strlen(token[1]));
    update_directory(dirstr, Cluster, Bytes_to_copy);
  }
  return 0;
}

void ls() {
  char filename[12];
  memset(filename, 0, 12);
  for (int i = 0; i < 16; i++) {
    // Check if the file is read only, a free entry, or entry sub-directory
    if (dir[i].DIR_Name[0] != 0xE5 && (dir[i].DIR_Attr == 0x01 ||
        dir[i].DIR_Attr == 10 || dir[i].DIR_Attr == 0x20)) {
      DirtoFileName(dir[i].DIR_Name, filename);
      printf("%s \n", dir[i].DIR_Name);
    }
  }
  printf("\n");
}

void del(char* token[]) {
  FiletoDirName(&token[1]);
  for(int i = 0; i < 16; i++) {
    if (strncmp(dir[i].DIR_Name, token[1], 11) == 0) {
      dir[i].DIR_Name[0] = '\xE5'; // Set to \xE5 to indicate the deleted state
      printf("File is deleted successfully.\n");
      break;
    }
  }
}

void undel(char* name) {
  for (int i = 0; i < 16; i++) {
    // Check if the file is deleted and if it is a file
    if (dir[i].DIR_Name[0] == '\xE5' && dir[i].DIR_Attr == 0x20) {
      dir[i].DIR_Name[0] = toupper(name[0]);
      printf("File undeleted successfully.\n");
      break;
    }
  }
}

// Finds the starting address of a block of data given the sector number
int LBAToOffset(int32_t sector) {
  return ((sector - 2) * BPB_BytesPerSec) + (BPB_BytesPerSec * BPB_RsvdSecCnt) +
  (BPB_NumFATs * BPB_FATSz32 * BPB_BytesPerSec);
}

/* Given a logical block address, look up into the first FAT and return the logical block
address of the block in the rifle. If there is no further block then return -1 */
int16_t NextLB(uint32_t sector) {
  uint32_t FATAddress = (BPB_BytesPerSec * BPB_RsvdSecCnt) + (sector * 4);
  int16_t val;
  fseek(fp, FATAddress, SEEK_SET);
  fread(&val, 2, 1, fp);
  return val;
}

// Change the file name to match the name in directory name
void FiletoDirName(char** name) {
  char expanded_name[12];
  memset(expanded_name, ' ', 11);

  char *token = strtok(*name, ".");

  strncpy(expanded_name, token, strlen(token));

  token = strtok(NULL, ".");

  if (token) {
    strncpy((char*)(expanded_name + 8), token, 3);
  }

  expanded_name[11] = '\0';

  for (int i = 0; i < 11; i++) {
    expanded_name[i] = toupper(expanded_name[i]);
  }

  strncpy(*name, expanded_name, 12);

}

// Update of new file info into directory entry
void update_directory(char* name, uint32_t cluster, uint32_t filesize) {
  struct DirectoryEntry* entry = (struct DirectoryEntry*) malloc(sizeof(struct DirectoryEntry));
  FiletoDirName(&name);
  strncpy(entry->DIR_Name, name, strlen(name));
  entry->DIR_Attr = 0x20;
  entry->DIR_FirstClusterHigh = (cluster >> 16) & 0xFFFF;
  entry->DIR_FirstClusterLow = cluster & 0xFFFF;
  entry->DIR_FileSize = filesize;
}

// Change the format of directory name into regular file name with extension
void DirtoFileName(char* dirname, char* filename) {
  for (int i = 0; i < 8; i++) {
    if (dirname[i] != ' ') {
      filename[i] = tolower(dirname[i]);
    }   
  }
  if (dirname[8] != ' ') {
    filename[8] = '.';
  }
  for (int i = 8; i < 11; i++) {
    if (dirname[i] != ' ') {
      filename[i + 1] = tolower(dirname[i]);
    }
  }
  filename[12] = '\0';
}
