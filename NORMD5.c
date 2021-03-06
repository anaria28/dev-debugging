// Knowledge and information sources : ps3devwiki.com | ps3hax.net | your friend google
// Thanks to all people sharing their findings and knowledge!
//
// Aim of this code:
//  dev / debugging purposes
//


//Generic includes for POSIX platforms
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/md5.h>

//Includes specific to the project.

#include "PS3Data.h"

#ifdef __MINGW32__
// for windows
#define MKDIR(x,y) mkdir(x)
#else
// for the real world
#define MKDIR(x,y) mkdir(x,y)
#endif

#define TYPE_HEX              0x00
#define TYPE_ASCII            0x01
#define DISPLAY_ALWAYS        0x02
#define DISPLAY_FAIL          0x04
#define DISPLAY_GOOD          0x08

#define NB_OPTIONS            9

#define OPTION_SPLIT          0x01
#define OPTION_MD5            0x02
#define OPTION_EXTRACT        0x04
#define OPTION_STATS          0x08
#define OPTION_CHECK_GENERIC  0x10
#define OPTION_CHECK_PERPS3   0x20
#define OPTION_DISPLAY_AREA   0x40
#define OPTION_CHECK_FILLED   0x80
#define OPTION_CHECK_NOT_ZERO 0x100
#define OPTION_CHECK_PER_FW   0x200

#define DATA_BUFFER_SIZE      0x100

struct Options {
    char       *Name;
    int        Type;
    uint32_t   Start;
    uint32_t   Size;
};

enum ReportChecking {
    ReportMD5 = 0,
    ReportExtraction,
    ReportStatistics,
    ReportGenericData,
    ReportPerConsoleData,
    ReportFilledArea,
    ReportNotZero,
    ReportPerFW,
    NBToReport
};

struct Reporting {
    uint8_t ReportNumber;
    char *ReportName;
    char *ReportMsg;
};

void MD5SumFileSection( FILE *FileToRead, uint32_t Position, uint32_t Size, uint8_t *Sum) {
    char *Buffer = malloc(Size+1);
    //uint8_t result[MD5_DIGEST_LENGTH];
    
    fseek (FileToRead, Position, SEEK_SET);
    fread (Buffer, Size, 1, FileToRead);
    MD5 (Buffer, Size, Sum);
}

void printMD5 (uint8_t MD5result[MD5_DIGEST_LENGTH]) {
    uint8_t Cursor;
    for(Cursor = 0; Cursor < MD5_DIGEST_LENGTH; Cursor++)
                printf("%02X",MD5result[Cursor]);
};

void GetSection(FILE *FileToRead, uint32_t Position, uint8_t Size, uint8_t DisplayType, char *section_data) {
    // Reads area from file and put it in section_data pointer
    // In Parameters:
    //  FILE *FileToRead     : File to read from
    //   uint32_t Position   : Offset to read from
    //   uint8_t Size        : Length of data to read
    //   uint8_t DisplayType : Print out in HEX or ASCII
    //   char *section_data  : Data to return
    
    uint16_t Cursor;
    *section_data=NULL;

    fseek(FileToRead, Position, SEEK_SET);

    if (((DisplayType)&(1<<0))==TYPE_HEX) {
        for (Cursor=0;Cursor<Size;Cursor++){
            sprintf(section_data, "%s%02X", section_data, fgetc(FileToRead));
        }
    }

    else if (((DisplayType)&(1<<0))==TYPE_ASCII) {
        fread(section_data, Size, 1, FileToRead);
        section_data[Size]=NULL;
    }
}

uint8_t CheckPerFW (FILE *FileToRead, uint32_t *PercentCheck){
    uint16_t Cursor=0;
    //uint8_t Cursor2=0;
    uint32_t SizedCheck=0;
    
    uint8_t Status =EXIT_SUCCESS;
    
    uint8_t MD5result[MD5_DIGEST_LENGTH];
    
    char    DisplaySection[DATA_BUFFER_SIZE]={0};

    uint8_t NbFileTOCros0;
    uint8_t NbFileTOCros1;
    
    uint32_t ros0Size;
    //uint32_t ros0FilledSize;
    uint32_t ros1Size;
    //uint32_t ros1FilledSize;
    uint32_t LastFileTOC;
    uint32_t LastFileOffset;
    uint32_t LastFileSize;
    
    uint32_t trvk_prg0Size;
    uint32_t trvk_prg1Size;
    uint32_t trvk_pkg0Size;
    uint32_t trvk_pkg1Size;
    
    char  ROS0SDKVersion[]="3.55";
    char  ROS1SDKVersion[]="3.41";

    char *Buffer = malloc(DATA_BUFFER_SIZE);

    struct Sections SectionRos[NB_MAX_FILE_ROS*2+1] = {
        {NULL, 0, 0, 0, 0, NULL}
    };
    
    printf("******************************\n");
    printf("*     Per Firmware Data      *\n");
    printf("******************************\n");
    
    /////////////////////////////////////////////////////////////////////////
    //  only for NAND -> http://www.ps3devwiki.com/wiki/Flash:ROS#Header   //
    /////////////////////////////////////////////////////////////////////////
    
    //http://www.ps3devwiki.com/wiki/Flash:ROS#ros_Entries
    //at ros0 offset + 0x14: nb of files, (nb of files) * 0x30 = size of TOC
    GetSection(FileToRead, SectionTOC[ros0].Offset+0x14, 0x04, TYPE_HEX, Buffer);
    NbFileTOCros0 = strtol(Buffer,NULL,16);
    
    SizedCheck += 0x04;
    
    if (NbFileTOCros0<NB_MAX_FILE_ROS) {
    
        for (Cursor=0;Cursor<NbFileTOCros0;Cursor++) {
            //www.ps3devwiki.com/wiki/Flash:ROS#Entry_Table
            
            GetSection(FileToRead, SectionTOC[ros0].Offset+0x20+Cursor*0x30, 0x08, TYPE_HEX, Buffer);
            SectionRos[Cursor].Offset = strtol(Buffer,NULL,16) + SectionTOC[ros0].Offset + 0x10;
            
            GetSection(FileToRead, SectionTOC[ros0].Offset+0x28+Cursor*0x30, 0x08, TYPE_HEX, Buffer);
            SectionRos[Cursor].Size = strtol(Buffer,NULL,16);
            
            GetSection(FileToRead, SectionTOC[ros0].Offset+0x30+Cursor*0x30, 0x20, TYPE_ASCII, Buffer);
            SectionRos[Cursor].name = strdup(Buffer);

            SizedCheck += SectionRos[Cursor].Size;
            
        }
    }
    else {
        printf ("Found %d files in the TOC of ros0, max is %d !\n" , NbFileTOCros0 , NB_MAX_FILE_ROS);
        return EXIT_FAILURE;
    }
    GetSection(FileToRead, SectionTOC[ros1].Offset+0x14, 0x04, TYPE_HEX, Buffer);
    NbFileTOCros1 = strtol(Buffer,NULL,16);
    
    SizedCheck += 0x04;
    
    if (NbFileTOCros1<NB_MAX_FILE_ROS) {
        //printf ("Found %d files in the TOC of ros1, max is %d !\n" , NbFileTOCros1 , NB_MAX_FILE_ROS);
        for (Cursor=0;Cursor<NbFileTOCros1;Cursor++) {
            //http://www.ps3devwiki.com/wiki/Flash:ROS#Entry_Table
            
            GetSection(FileToRead, SectionTOC[ros1].Offset+0x20+Cursor*0x30, 0x08, TYPE_HEX, Buffer);
            SectionRos[Cursor+NbFileTOCros0].Offset = strtol(Buffer,NULL,16) + SectionTOC[ros1].Offset + 0x10;
            
            GetSection(FileToRead, SectionTOC[ros1].Offset+0x28+Cursor*0x30, 0x08, TYPE_HEX, Buffer);
            SectionRos[Cursor+NbFileTOCros0].Size = strtol(Buffer,NULL,16);
            
            GetSection(FileToRead, SectionTOC[ros1].Offset+0x30+Cursor*0x30, 0x20, TYPE_ASCII, Buffer);
            SectionRos[Cursor+NbFileTOCros0].name=strdup(Buffer);
            
            SizedCheck += SectionRos[Cursor+NbFileTOCros0].Size;
        }
    }
    else {
        printf ("Found %d files in the TOC of ros1, max is %d !\n" , NbFileTOCros1 , NB_MAX_FILE_ROS);
        return EXIT_FAILURE;
    }
    
    Cursor = 0;
    while (SectionRos[Cursor].name!=NULL) {
        if (strcmp(SectionRos[Cursor].name, "sdk_version")==0) {
            GetSection(FileToRead, SectionRos[Cursor].Offset, SectionRos[Cursor].Size, TYPE_ASCII, Buffer);
            if (Cursor<=NbFileTOCros0) {
                ROS0SDKVersion[0]=Buffer[0];
                ROS0SDKVersion[2]=Buffer[1];
                ROS0SDKVersion[3]=Buffer[2];
                }
            else {
                ROS1SDKVersion[0]=Buffer[0];
                ROS1SDKVersion[2]=Buffer[1];
                ROS1SDKVersion[3]=Buffer[2];
            }
            //printf (" SDK VERSION at '0x%08X' is : '%7s'\n",SectionRos[Cursor].Offset, Buffer);
            //printf ("%s\n",DisplaySection);
        }
        Cursor++;
    }
    //at ros0 offset + 0x14: nb of files, (nb of files) * 0x30 = size of TOC
    GetSection(FileToRead, SectionTOC[ros0].Offset+0x14, 0x04, TYPE_HEX, Buffer);
    LastFileTOC = (strtol(Buffer,NULL,16))*0x30-0x10;
 
    //last file position found at (ros0 offset) + (size of TOC) - 0x10
    GetSection(FileToRead, SectionTOC[ros0].Offset+LastFileTOC, 0x08, TYPE_HEX, Buffer);
    LastFileOffset = strtol(Buffer,NULL,16);
 
    //+ 0x8 for its size.
    GetSection(FileToRead, SectionTOC[ros0].Offset+LastFileTOC+0x08, 0x08, TYPE_HEX, Buffer);
    LastFileSize = strtol(Buffer,NULL,16);
 
    ros0Size = 0x10 + LastFileOffset + LastFileSize;
    //From end of last file pos + size to next section - 0x10 : full of 00
    //last 0x10 bytes are full of FF !!??

    //at ros1 offset + 0x14: nb of files, (nb of files) * 0x30 = size of TOC
    GetSection(FileToRead, SectionTOC[ros1].Offset+0x14, 0x04, TYPE_HEX, Buffer);
    LastFileTOC = (strtol(Buffer,NULL,16))*0x30-0x10;
    //last file position found at (ros1 offset) + (size of TOC) - 0x10
 
    GetSection(FileToRead, SectionTOC[ros1].Offset+LastFileTOC, 0x08, TYPE_HEX, Buffer);
    LastFileOffset = strtol(Buffer,NULL,16);
 
    //+ 0x8 for its size.
    GetSection(FileToRead, SectionTOC[ros1].Offset+LastFileTOC+0x08, 0x08, TYPE_HEX, Buffer);
    LastFileSize = strtol(Buffer,NULL,16);
 
    ros1Size = 0x10 + LastFileOffset + LastFileSize;
    
    printf ("{\"ros0\" , \"");
    MD5SumFileSection (FileToRead, SectionTOC[ros0].Offset+0x10, ros0Size, MD5result);
    printf("%c.%c%c\" , \"", ROS0SDKVersion[0],ROS0SDKVersion[2],ROS0SDKVersion[3]);
    printMD5(MD5result);
    printf ("\"}, // ros0Size:'0x%08X'\n",ros0Size);
    
    printf ("{\"ros1\" , \"");
    MD5SumFileSection (FileToRead, SectionTOC[ros1].Offset+0x10, ros1Size, MD5result);
    printf("%c.%c%c\" , \"", ROS1SDKVersion[0],ROS1SDKVersion[2],ROS1SDKVersion[3]);
    printMD5(MD5result);
    printf ("\"}, // ros1Size:'0x%08X'\n",ros1Size);
    
    printf("\n");
    
    Cursor = 0;
    while (SectionRos[Cursor].name!=NULL) {
            printf ("{\"%s\" , \"",SectionRos[Cursor].name);
            
            MD5SumFileSection ( FileToRead, SectionRos[Cursor].Offset, SectionRos[Cursor].Size, MD5result);

            // printf ("\"},\n");
            if (Cursor<NbFileTOCros0) {
                printf("%c.%c%c\" , \"", ROS0SDKVersion[0],ROS0SDKVersion[2],ROS0SDKVersion[3]);
                }
            else {
                printf("%c.%c%c\" , \"", ROS1SDKVersion[0],ROS1SDKVersion[2],ROS1SDKVersion[3]);
            }
            //printf (" SDK VERSION at '0x%08X' is : '%7s'\n",SectionRos[Cursor].Offset, Buffer);
            printMD5(MD5result);
            printf ("\"},\n");

        Cursor++;
    }
    printf ("\n");
    printf ("{\"trvk_prg0\" , \"");
    MD5SumFileSection (FileToRead, SectionTOC[trvk_prg0].Offset+0x10, 0x0FE0, MD5result);
    printMD5(MD5result);
    printf ("\"},\n");
    
    GetSection(FileToRead, SectionTOC[trvk_prg0].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
    trvk_prg0Size = strtol(Buffer,NULL,16);
    
    printf ("2nd MD5: \"");
    MD5SumFileSection (FileToRead, SectionTOC[trvk_prg0].Offset+0x10, trvk_prg0Size, MD5result);
    printMD5(MD5result);
    printf("\"\n");
    
    printf ("{\"trvk_prg1\" , \"");
    MD5SumFileSection (FileToRead, SectionTOC[trvk_prg1].Offset+0x10, 0x0FE0, MD5result);
    printMD5(MD5result);
    printf ("\"},\n");
    
    GetSection(FileToRead, SectionTOC[trvk_prg1].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
    trvk_prg1Size = strtol(Buffer,NULL,16);
    
    printf ("2nd MD5: \"");
    MD5SumFileSection (FileToRead, SectionTOC[trvk_prg1].Offset+0x10, trvk_prg1Size, MD5result);
    printMD5(MD5result);
    printf("\"\n");
    
    printf ("{\"trvk_pkg0\" , \"");
    MD5SumFileSection (FileToRead, SectionTOC[trvk_pkg0].Offset+0x10, 0x0FE0, MD5result);
    printMD5(MD5result);
    printf ("\"},\n");
    
    GetSection(FileToRead, SectionTOC[trvk_pkg0].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
    trvk_pkg0Size = strtol(Buffer,NULL,16);
    
    printf ("2nd MD5: \"");
    MD5SumFileSection (FileToRead, SectionTOC[trvk_pkg0].Offset+0x10, trvk_pkg0Size, MD5result);
    printMD5(MD5result);
    printf("\"\n");
    
    printf ("{\"trvk_pkg1\" , \"");
    MD5SumFileSection (FileToRead, SectionTOC[trvk_pkg1].Offset+0x10, 0x0FE0, MD5result);
    printMD5(MD5result);
    printf ("\"},\n");
    
    GetSection(FileToRead, SectionTOC[trvk_pkg1].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
    trvk_pkg1Size = strtol(Buffer,NULL,16);
    
    printf ("2nd MD5: \"");
    MD5SumFileSection (FileToRead, SectionTOC[trvk_pkg1].Offset+0x10, trvk_pkg1Size, MD5result);
    printMD5(MD5result);
    printf("\"\n");
    
    // The MD5 is done on 0x0FE0, but some blanks where checked before in CheckFilledData()
    // To avoid having a false report on the size checked here we do count on the size of data only
    
    GetSection(FileToRead, SectionTOC[trvk_prg0].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
    trvk_prg0Size = strtol(Buffer,NULL,16); //.Yes it can be done in one line
    SizedCheck += trvk_prg0Size;            // but this way is selfexplaining
    
    GetSection(FileToRead, SectionTOC[trvk_prg1].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
    trvk_prg1Size = strtol(Buffer,NULL,16);
    SizedCheck += trvk_prg1Size; 
     
    GetSection(FileToRead, SectionTOC[trvk_pkg0].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
    trvk_pkg0Size = strtol(Buffer,NULL,16);
    SizedCheck += trvk_pkg0Size; 
    
    GetSection(FileToRead, SectionTOC[trvk_pkg1].Offset+0x0E, 0x02, TYPE_HEX, Buffer);
    trvk_pkg1Size = strtol(Buffer,NULL,16);
    SizedCheck += trvk_pkg1Size; 
    
    *PercentCheck = SizedCheck;

    free(Buffer);
    return Status;
}

int main(int argc, char *argv[]) {
    uint8_t  Status = EXIT_SUCCESS;
    uint8_t  GlobalStatus = EXIT_SUCCESS;
    FILE     *BinaryFile;
    uint32_t FileLength;
    char     *Buffer = malloc(DATA_BUFFER_SIZE);
    uint8_t  Cursor;
    int      OptionType=0;
    struct   Options Option[NB_OPTIONS];
    //uint32_t ExtractionSize;
   //char     DisplaySection[DATA_BUFFER_SIZE];
    uint32_t *SizedCheck = malloc(sizeof(uint32_t)+1);
    //uint32_t GlobalSizedCheck=0;
    //uint8_t  GlobalReport[NBToReport]={0};
    uint8_t MD5result[MD5_DIGEST_LENGTH];
    

    printf("******************************\n");
    printf("*       dev-debugging        *\n");
    printf("******************************\n");

    printf("\nOpen source project aimed to help to for me for my PS3 NOR dumps\n");

    if ((argc < 2)||(strcmp(argv[1], "--help")==0)) {
        printf("Usage: %s NorFile.bin (Options)\n", argv[0]);
        printf("Options:\n");
        printf("  --help\t\t: Display this help.\n");
        //printf("  -P \t\t\t: Give percentage of bytes\n");
        //printf("  -G \t\t\t: Check PS3 Generic information\n");
        //printf("  -C \t\t\t: Check and display perconsole information\n");
        //printf("  -f \t\t\t: Check areas filled with '00' or 'FF'\n");
        printf("  -F \t\t\t:(Default option if none given) display some MD5 on Firmware information (ros0/1 + trvk)\n");
        //printf("  -N \t\t\t: Check areas containing data in opposition to -F option\n");
        //printf("  -S FolderName \t: Split some NOR section to folder 'FolderName'\n");
        printf("  -M Start Size \t: Run MD5 sum on file from 'Start' for 'Size' long\n");
        //printf("  -E FileName Start Size: Extract specific NOR Section from 'Start' for 'Size' long\n");
        //printf("  -D Start Size H/A \t: Display a specific NOR Section \n\t\t\t  from 'Start' for 'Size' long, use H or A for HEX or ASCII\n");
        //printf("\nBy default -P -G -C -f and -F will be applied if no option is given\n");
        printf("\nRepo: <https://github.com/anaria28/dev-debugging>\n");
        //     "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789
        //     "         1         2         3         4         5         6         7         8
        return EXIT_FAILURE;
    }

    if (argc==2) {
        OptionType = OPTION_CHECK_PER_FW;
    }

    for (Cursor=1;Cursor<argc;Cursor++) {

        if (strcmp(argv[Cursor], "-M")==0) {
            OptionType += OPTION_MD5;
            Option[1].Start = strtol(argv[Cursor+1],NULL,0);
            Option[1].Size = strtol(argv[Cursor+2],NULL,0);
        }

        if (strcmp(argv[Cursor], "-F")==0){
            OptionType += OPTION_CHECK_PER_FW;
        }
    }

    BinaryFile = fopen(argv[1], "rb");
    if (!BinaryFile) {
        printf("Failed to open %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    fseek(BinaryFile, 0, SEEK_END);
    if ((FileLength=ftell(BinaryFile))!=NOR_FILE_SIZE) {
        printf("File size not correct for NOR, %d Bytes instead of %d\n", FileLength, NOR_FILE_SIZE);
        return EXIT_FAILURE;
    }

    if (((OptionType)&(1<<1))==OPTION_MD5) {
        printf("******************************\n");
        printf("*     MD5 Sum on Section     *\n");
        printf("******************************\n");
        printf("Chosen section MD5 sum is: ");
        MD5SumFileSection( BinaryFile, Option[1].Start, Option[1].Size, MD5result);
        printMD5(MD5result);
        printf ("\n");
    }
    
    if (((OptionType)&(1<<9))==OPTION_CHECK_PER_FW) {
        if((Status = CheckPerFW(BinaryFile, SizedCheck))) {
            printf("T'a merde mon gars...\n");
        }
        else {
            printf("C'est bon!\n");
        }
    }
    
    free(Buffer);
    fclose(BinaryFile);
    
    return GlobalStatus;
}