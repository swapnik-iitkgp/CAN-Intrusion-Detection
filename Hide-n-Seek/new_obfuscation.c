/*****************************************************************
 *  sched_attack.c  —  Attack-window analyser with string IDs
 *  build:  gcc -std=c11 -Wall -O2  sched_attack.c -o sched_attack
 *  usage:  ./sched_attack  <SampleTwo.csv>  [-i id1,id2,...]
 *****************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <unistd.h>   /* getopt() */

/* ─── strsep shim (Windows / MinGW lacks it) ───────────── */
#ifndef HAVE_STRSEP
static char *strsep(char **stringp, const char *delim)
{
    char *s  = *stringp;
    if (s == NULL) return NULL;
    char *end = strpbrk(s, delim);
    if (end) *end++ = '\0';
    *stringp = end;
    return s;
}
#endif

#undef DEBUG
#ifdef DEBUG
#define PRINT printf
#else
#define PRINT(...)
#endif

/* ─────────────  compile-time defaults  ─────────────────────── */
// #define IDLEN  8                 /* e.g. "0x7FF" + NUL         */
// #define ECU_COUNT_DEFAULT 4
// const char *ECUIDs[ECU_COUNT_DEFAULT] = {"0x01A1","0x01C3","0x02C3","0x03D1"};
// float  ECUIDPeriodicities[ECU_COUNT_DEFAULT] = {0.025f,0.025f,0.05f,0.10f};
// int    ctrlSkipLimit[ECU_COUNT_DEFAULT]      = {3,2,2,1};

/* ─────────────  compile-time defaults  ─────────────────────── */
#define IDLEN  8                 /* e.g. "0x7FF" + NUL         */
#define ECU_COUNT_DEFAULT 45

const char *ECUIDs[ECU_COUNT_DEFAULT] = {
    "0018","0034","0042","0043","0044",
    "0050","0080","0081","00A0","00A1",
    "0110","0120","0153","0164","0165",
    "018F","01F1","0220","0260","02A0",
    "02B0","02C0","0316","0329","0350",
    "0370","0382","043F","0440","04B0",
    "04B1","04F0","04F1","04F2","0510",
    "0517","051A","0545","0587","059B",
    "05A0","05A2","05E4","05F0","0690"
};

float  ECUIDPeriodicities[ECU_COUNT_DEFAULT] = {0.026988043264503627, 0.026828728323698293, 0.01585848101265897, 0.023624161490683127, 0.02078586419753139, 0.02093232558139584, 0.028108898987434287, 0.024965516660652082, 0.024593351648351747, 0.027704358974358474, 0.028386444706344424, 0.023791045845272023, 0.026170660655737775, 0.026622148319145906, 0.02722151097569439, 0.025358991971992432, 0.02537005559990087, 0.02590854346727021, 0.025587578832910508, 0.026874992878816062, 0.027907885307291196, 0.026379919097430683, 0.027847601741243157, 0.02463998929807993, 0.025709633534136547, 0.02590638691145254, 0.0265241197399092, 0.027798296367341983, 0.02644186291850913, 0.025765260102701606, 0.026482078131069186, 0.02703256364562113, 0.025988899022800823, 0.027684599669343675, 0.025836751980499804, 0.025342299605781715, 0.030323516624042004, 0.027549642296625664, 0.025941695730606958, 0.024413155497723226, 0.026082199692163445, 0.02707124161416649, 0.025302135338346014, 0.025395944767441805, 0.025491126860382504};
int  ctrlSkipLimit[ECU_COUNT_DEFAULT] = {
    3,1,2,2,4,  3,1,1,2,3,
    4,2,1,3,2,  4,4,1,2,3,
    3,1,2,4,1,  3,2,2,4,1,
    3,2,1,4,3,  2,2,1,4,3,
    1,2,3,4,2
};


// const char *ECUIDs[ECU_COUNT_DEFAULT] = {
//     "0x0018","0x0034","0x0042","0x0043","0x0044",
//     "0x0050","0x0080","0x0081","0x00A0","0x00A1",
//     "0x0110","0x0120","0x0153","0x0164","0x0165",
//     "0x018F","0x01F1","0x0220","0x0260","0x02A0",
//     "0x02B0","0x02C0","0x0316","0x0329","0x0350",
//     "0x0370","0x0382","0x043F","0x0440","0x04B0",
//     "0x04B1","0x04F0","0x04F1","0x04F2","0x0510",
//     "0x0517","0x051A","0x0545","0x0587","0x059B",
//     "0x05A0","0x05A2","0x05E4","0x05F0","0x0690"
// };

/* ─────────────  run-time indirection  ──────────────────────── */
const char **ECUIDsArr      = ECUIDs;
float  *ECUIDPeriodsArr     = ECUIDPeriodicities;
int    *ctrlSkipLimitArr    = ctrlSkipLimit;
int     ECUCountVar         = ECU_COUNT_DEFAULT;

/* ─────────────  global parameters  ─────────────────────────── */
int   h            = 5;         /* CAN hyper-period (s)            */
int   minAtkWinLen = 111;       /* bits                             */
int   minDlc       = 7;         /* bytes                            */
float busSpeed     = 500;       /* kbps                             */
const char *testID = "0x01CD";  /* for debug prints                 */

/* ─────────────  data structures  ───────────────────────────── */
struct Instance{
    int   index;
    int   atkWinLen;
    int   atkWinCount;
    int   attackable;
    int  *atkWin;
    int  *insWin;
};

struct Message{
    char  ID[IDLEN];
    float periodicity;
    int   count;
    int   DLC;
    float txTime;
    int   atkWinLen;
    int   tAtkWinLen;
    int   tAtkWinCount;
    int   readCount;
    int  *tAtkWin;
    int  *tInsWin;
    struct Instance *instances;
    int  *sortedASP;
    int  *pattern;
    int   skipLimit;
};

/* ─────────────  helper: numeric form of an ID string  ───────── */
static inline long id_to_long(const char *id)
{
    return strtol(id, NULL, 0);      /* "0x0220" or "220" both ok */
}

/* ─────────────  ECU initialisation  ─────────────────────────── */
void InitializeECU(struct Message **S)
{
    for(int i=0;i<ECUCountVar;i++){
        strncpy((*S)[i].ID, ECUIDsArr[i], IDLEN);
        (*S)[i].periodicity = ECUIDPeriodsArr[i];
        (*S)[i].count       = ceil(h/(*S)[i].periodicity);
        (*S)[i].DLC = (*S)[i].atkWinLen = (*S)[i].tAtkWinLen =
        (*S)[i].tAtkWinCount = (*S)[i].readCount = 0;
        (*S)[i].instances = calloc((*S)[i].count,sizeof(struct Instance));
        (*S)[i].sortedASP = calloc((*S)[i].count,sizeof(int));
        (*S)[i].pattern   = calloc((*S)[i].count,sizeof(int));
        (*S)[i].skipLimit = ctrlSkipLimitArr[i];
        for(int j=0;j<(*S)[i].count;j++){
            (*S)[i].instances[j].index = j;
            (*S)[i].pattern[j] = 1;
        }
    }
}

/* ------------------------------------------------------------------
   Read one CAN log CSV (Vector-style header shown by you) into a
   dynamically-growing array of struct Message.  Works even when some
   data-byte columns are empty, because it uses strsep() which keeps
   empty tokens.
   ------------------------------------------------------------------ */
   #include <ctype.h>     /* isspace() */
   #include <errno.h>
   
int InitializeCANTraffic(struct Message **out, const char *csvFile)
   {
       FILE *fp = fopen(csvFile, "r");
       if (!fp) { perror(csvFile); return -1; }
   
       char  line[4096];
       int   row = 0, used = 0;
   
       /* throw away the header line */
       if (!fgets(line, sizeof line, fp)) { fclose(fp); return 0; }
   
       while (fgets(line, sizeof line, fp))
       {
           /* remove trailing CR/LF */
           size_t len = strlen(line);
           while (len && isspace((unsigned char)line[len-1])) line[--len] = '\0';
   
           /* enlarge array and zero the freshly created struct            */
           *out = realloc(*out, (used+1) * sizeof(**out));
           struct Message *msg = &(*out)[used];
           memset(msg, 0, sizeof *msg);
   
           /* split ----------------------------------------------------------------*/
           char *save = line, *tok;
           int   col  = 0;
           while ((tok = strsep(&save, ",")) != NULL)
           {
               switch (col)                      /* only columns we care about  */
               {
                    case 1:                       /* Identifier -----------------*/
                        /* add "0x" if the token doesn’t already have it */
                        if (tok[0]=='0' && (tok[1]=='x' || tok[1]=='X'))
                            strncpy(msg->ID, tok, IDLEN-1);        /* already has 0x */
                        else
                            snprintf(msg->ID, IDLEN, "0x%s", tok); /* prepend 0x     */
                        msg->ID[IDLEN-1] = '\0';
                        break;
   
                   case 2:                       /* DLC ------------------------*/
                       /* defensive: empty DLC ⇒ 0                                */
                       msg->DLC = (*tok) ? atoi(tok) : 0;
                       break;
   
                   case 11:                      /* Time -----------------------*/
                       msg->txTime = strtof(tok, NULL);
                       break;
               }
               ++col;
           }
   
           /* basic sanity – ignore lines without identifier OR time -------------*/
           if (msg->ID[0] && msg->txTime > 0.0f)
               ++used;
       }
       fclose(fp);
       return used;           /* number of packets successfully parsed */
   }
   

// merge two sorted arrays
void IntMerge(int *arr, int *temp, int l, int m, int r)
{
    int i, j, k;
    int n1 = m - l + 1;
    int n2 = r - m;

    // Create temp arrays
    int *L  = malloc(n1 * sizeof *L);
    int *R  = malloc(n2 * sizeof *R);
    int *L1 = malloc(n1 * sizeof *L1);
    int *R1 = malloc(n2 * sizeof *R1);

    if(!L || !L1 || !R || !R1){ perror("malloc"); exit(EXIT_FAILURE); }

    // Copy data to temp arrays L[] and R[]
    for (i = 0; i < n1; i++)
    {
        L[i] = arr[l + i];
        L1[i] = temp[l+i];
    }for (j = 0; j < n2; j++){
        R[j] = arr[m + 1 + j];
        R1[j] = temp[m + 1 + j];
    }

    // Merge the temp arrays back into arr[l..r
    i = 0;
    j = 0;
    k = l;
    while (i < n1 && j < n2) {
        if (L[i] <= R[j]) {
            arr[k] = L[i];
            temp[k] = L1[i];
            i++;
        }
        else {
            arr[k] = R[j];
            temp[k] = R1[j];
            j++;
        }
        k++;
    }

    // Copy the remaining elements of L[],
    // if there are any
    while (i < n1) {
        arr[k] = L[i];
        temp[k] = L1[i];
        i++;
        k++;
    }

    // Copy the remaining elements of R[],
    // if there are any
    while (j < n2) {
        arr[k] = R[j];
        temp[k] = R1[j];
        j++;
        k++;
    }

    free(R);  free(L);  free(R1);  free(L1);
    
}

// To sort an array of integers
// l and r are left and right most index of arr
void IntSort(int *arr1, int *arr2, int l, int r)
{
    if (l < r) {
        int m = l + (r - l) / 2;

        // Sort first and second halves
        IntSort(arr1, arr2, l, m);
        IntSort(arr1, arr2, m + 1, r);
        IntMerge(arr1, arr2, l, m, r);
    }

}

// Merge two lists of mesages sorted by attack length
void MsgMergeByAtkWinLen(struct Message **arr, int l, int m, int r)
{
    int i, j, k;
    int n1 = m - l + 1;
    int n2 = r - m;

    // Create temp arrays
    struct Message *L = malloc(n1 * sizeof *L);
    struct Message *R = malloc(n2 * sizeof *R);
    if(!L || !R){ perror("malloc"); exit(EXIT_FAILURE); }


    // Copy data to temp arrays L[] and R[]
    for (i = 0; i < n1; i++)
        L[i] = (*arr)[l + i];
    for (j = 0; j < n2; j++)
        R[j] = (*arr)[m + 1 + j];

    // Merge the temp arrays back into arr[l..r
    i = 0;
    j = 0;
    k = l;
    while (i < n1 && j < n2) {
        if (L[i].atkWinLen <= R[j].atkWinLen) {
            (*arr)[k] = L[i];
            i++;
        }
        else {
            (*arr)[k] = R[j];
            j++;
        }
        k++;
    }

    // Copy the remaining elements of L[],
    // if there are any
    while (i < n1) {
        (*arr)[k] = L[i];
        i++;
        k++;
    }

    // Copy the remaining elements of R[],
    // if there are any
    while (j < n2) {
        (*arr)[k] = R[j];
        j++;
        k++;
    }
    PRINT("\n In MsgMergeByAtkWinLen: Freeing L");
    free(L);
    PRINT("\n In MsgMergeByAtkWinLen: Freeing R");
    free(R);
}


// To sort a message list by their attack length in ascending order
void MsgSortByAtkWinLen(struct Message **candidates, int l, int r)
{
        if (l < r) {
            int m = l + (r - l) / 2;
            // Sort first and second halves
            MsgSortByAtkWinLen(candidates, l, m);
            MsgSortByAtkWinLen(candidates, m + 1, r);
            MsgMergeByAtkWinLen(candidates, l, m, r);
    }

}

// Merge two lists of instances sorted by attack length
void InsMergeByAtkWinLen(struct Instance **instances, int l, int m, int r)
{
    int i, j, k;
    int n1 = m - l + 1;
    int n2 = r - m;

    // Create temp arrays
    struct Instance *L = malloc(n1 * sizeof *L);
    struct Instance *R = malloc(n2 * sizeof *R);

    if(!L || !R){ perror("malloc"); exit(EXIT_FAILURE); }

    // Copy data to temp arrays L[] and R[]
    for (i = 0; i < n1; i++)
        L[i] = (*instances)[l + i];
    for (j = 0; j < n2; j++)
        R[j] = (*instances)[m + 1 + j];

    // Merge the temp arrays back into arr[l..r]
    i = 0;
    j = 0;
    k = l;
    while (i < n1 && j < n2) {
        if (L[i].atkWinLen >= R[j].atkWinLen) {
            (*instances)[k] = L[i];
            i++;
        }
        else {
            (*instances)[k] = R[j];
            j++;
        }
        k++;
    }
    // Copy the remaining elements of L[],
    // if there are any
    while (i < n1) {
        (*instances)[k] = L[i];
        i++;
        k++;
    }
    // Copy the remaining elements of R[],
    // if there are any
    while (j < n2) {
        (*instances)[k] = R[j];
        j++;
        k++;
    }
    PRINT("\n In InsMergeByAtkWinLen: Freeing L");
    free(L);
    PRINT("\n In InsMergeByAtkWinLen: Freeing R");
    free(R);
}

// To sort the instances in descending order of atk success prob. i.e. atk win len
void InsSortByAtkWinLen(struct Instance **instances, int l, int r)
{
    if (l < r) {
            int m = l + (r - l) / 2;
            // Sort first and second halves
            InsSortByAtkWinLen(instances, l, m);
            InsSortByAtkWinLen(instances, m + 1, r);
            InsMergeByAtkWinLen(instances, l, m, r);
    }
}

int BinarySearch(int *arr, int l, int r, int x)
{
    while (l <= r) {
        int m = l + (r - l) / 2;

        // Check if x is present at mid
        if (arr[m] == x)
        {
            //printf("\n array element=%d, item to be searched=%d", arr[m],x);
            return m;
        }
        // If x greater, ignore left half
        if (arr[m] < x)
            l = m + 1;

        // If x is smaller, ignore right half
        else
            r = m - 1;
    }

    // If we reach here, then element was not present
    return -1;
}

// Returns the intersection of two arrays and b
// Update attack window of instance ins with the common messages
void CommonMessages(int *a, int *x, int n_a, int *b, int *y, int n_b, struct Instance *ins)
{
    int j = 0, i=0, k=0;
    int atkWinCount = 0;
    int *intersection;
    int *intersection1;
    if(n_a<=n_b)
    {
        IntSort(a, x, 0, n_a-1);
        for(i=0;i<n_b;i++)
        {
            if(BinarySearch(a, 0, n_a-1, b[i])>=0)
            {
                j++;
                if(j==1)
                {
                    intersection = (int *)calloc(j, sizeof(int));
                    intersection1 = (int *)calloc(j, sizeof(int));
                }else
                {
                    intersection = (int *)realloc(intersection, sizeof(int)*j);
                    intersection1 = (int *)realloc(intersection1, sizeof(int)*j);
                }
                intersection[j-1] = b[i];
                intersection1[j-1] = y[i];
                atkWinCount++;
            }
        }
    }
    else
    {
        IntSort(b, y, 0, n_b-1);
        for(i=0;i<n_a;i++)
        {
            if(BinarySearch(b, 0, n_b-1, a[i])>=0)
            {
                j++;
                if(j==1)
                {
                    intersection = (int *)calloc(j, sizeof(int));
                    intersection1 = (int *)calloc(j, sizeof(int));
                }else
                {
                    intersection = (int *)realloc(intersection, sizeof(int)*j);
                    intersection1 = (int *)realloc(intersection1, sizeof(int)*j);
                }
                intersection[j-1] = a[i];
                intersection1[j-1] = x[i];
                atkWinCount++;
            }
        }
    }
    PRINT("\n In common: freeing atkWin");
    free((*ins).atkWin);
    PRINT("\n In common: freeing insWin");
    free((*ins).insWin);
    (*ins).atkWinCount = atkWinCount;
    PRINT("\n In Common: atkWinCount = %d",atkWinCount);
    if(atkWinCount>0)
    {
        (*ins).atkWin = (int *)calloc(atkWinCount, sizeof(int));
        (*ins).insWin = (int *)calloc(atkWinCount, sizeof(int));
        for(int i=0;i<atkWinCount;i++)
        {
            (*ins).atkWin[i] = intersection[i];
            (*ins).insWin[i] = intersection1[i];
        }
        PRINT("\n In common: freeing intersection1");
        free(intersection);
        PRINT("\n In common: freeing intersection2");
        free(intersection1);
    }
}

/* ─────────────  GetCurrentInstance (string arg)  ───────────── */
int GetCurrentInstance(struct Message **cand, const char *id)
{
    for(int i=0;i<ECUCountVar;i++)
        if(strcmp((*cand)[i].ID,id)==0) return (*cand)[i].readCount;
    return -1;
}

void AnalyzeCANTraffic(struct Message *CANTraffic, int CANCount, struct Message **candidates)
{
    int j=0,i=0,k=0,l=0,insNo = 0;
    float txStart = 0, txEnds = 0, nextTxStart = 0;
    float maxIdle = (minDlc*8+47)/(busSpeed*1000);
    struct Message CANPacket, candidate;
    while(j<CANCount-1)
    {
        CANPacket = CANTraffic[j];
        txStart = CANPacket.txTime;
        long idPkt = id_to_long(CANPacket.ID);
        txEnds = ((CANPacket.DLC)*8 + 47)/(busSpeed*1000);
        nextTxStart = CANTraffic[j+1].txTime;
        PRINT("\n Checking for CAN ID (%d):%d ***********************",j,CANPacket.ID);
        for(i=0;i<ECUCountVar;i++)
        {
            long idEcu = id_to_long((*candidates)[i].ID);          /* NEW */
            PRINT("\n Checking ECU ID:%s ***********************",(*candidates)[i].ID);
            k = 0;
            for (l = (*candidates)[i].readCount; l < (*candidates)[i].count; l++)
            {
                if((*candidates)[i].pattern[l]==0)
                    k++;
            }
            if (idEcu == id_to_long(testID))
            {
                printf("\n max idle time=%f",maxIdle);
                printf("\n gap = %f",(nextTxStart - (txStart + txEnds)));
            }
            if((idPkt > idEcu) || ((nextTxStart-(txStart+txEnds))>maxIdle && (idPkt != idEcu))) // If CAN packet is of lower priority or there is an idle period in between
            {
                if((*candidates)[i].tAtkWinLen>0)
                {
                    PRINT("\n freeing tAtkWin in low priority case");
                    free((*candidates)[i].tAtkWin);
                    PRINT("\n freeing tInsWin in low priority case");
                    free((*candidates)[i].tInsWin);
                    (*candidates)[i].tAtkWinLen = 0;
                    (*candidates)[i].tAtkWinCount = 0;
                }
            }
            else if(idPkt < idEcu)
            {
                insNo = GetCurrentInstance(candidates,CANPacket.ID);
                // what is instance no. of the CANPacket if it is coming from target ECU
                (*candidates)[i].tAtkWinCount = (*candidates)[i].tAtkWinCount + 1;
                (*candidates)[i].tAtkWinLen = (*candidates)[i].tAtkWinLen + (CANPacket.DLC)*8 + 47;
                if((*candidates)[i].tAtkWinCount == 1)
                {
                    (*candidates)[i].tAtkWin = (int *)calloc((*candidates)[i].tAtkWinCount,sizeof(int));
                    (*candidates)[i].tInsWin = (int *)calloc((*candidates)[i].tAtkWinCount,sizeof(int));
                }
                else
                {
                    (*candidates)[i].tAtkWin = (int *)realloc((*candidates)[i].tAtkWin,sizeof(int)*(*candidates)[i].tAtkWinCount);
                    (*candidates)[i].tInsWin = (int *)realloc((*candidates)[i].tInsWin,sizeof(int)*(*candidates)[i].tAtkWinCount);
                }
                (*candidates)[i].tAtkWin[(*candidates)[i].tAtkWinCount-1] = idPkt;
                (*candidates)[i].tInsWin[(*candidates)[i].tAtkWinCount-1] = insNo;
            }
            else
            {
                if((*candidates)[i].readCount>=(*candidates)[i].count) // 2nd hyper period onwards
                {

                    (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinLen
                                = (int)fmin((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinLen, (*candidates)[i].tAtkWinLen);
                    if((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinLen == 0)
                    {
                        (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount = 0;
                        (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWin =
                                                            (int *)calloc((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount,sizeof(int));
                        (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].insWin =
                                                            (int *)calloc((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount,sizeof(int));
                    }
                    else{
                    CommonMessages((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWin,
                                   (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].insWin,
                                   (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount,
                                   (*candidates)[i].tAtkWin,
                                   (*candidates)[i].tInsWin,
                                   (*candidates)[i].tAtkWinCount,
                                   &(*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count]);
                    }
                }
                else // 1st hyper period
                {

                    (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinLen = (*candidates)[i].tAtkWinLen;
                    (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount = (*candidates)[i].tAtkWinCount;
                    (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWin =
                                                            (int *)calloc((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount,sizeof(int));
                    (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].insWin =
                                                            (int *)calloc((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount,sizeof(int));
                    for(l=0;l<(*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount;l++)
                    {
                        (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWin[l] = (*candidates)[i].tAtkWin[l];
                        (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].insWin[l] = (*candidates)[i].tInsWin[l];
                    }
                }

                if((*candidates)[i].tAtkWinLen>0)
                {
                    PRINT("\n freeing tAtkWin at end");
                    free((*candidates)[i].tAtkWin);
                    PRINT("\n freeing tInsWin at end");
                    free((*candidates)[i].tInsWin);
                    (*candidates)[i].tAtkWinLen = 0;
                    (*candidates)[i].tAtkWinCount = 0;
                }
                (*candidates)[i].readCount=(*candidates)[i].readCount+k+1;
            }
        }
        j++;
    }
}

// This function checks if a new skip is introduced in the existing pattern
// the CLF criteria is violated or not.
int IfSkipPossible(int *patternList, int patternLen, int skipLimit, int newSkipPosition)
{
    int i=0, sum=0;
    patternList[newSkipPosition] = 0;

    for(i=0;i<patternLen;i++)
    {
        if(patternList[i%patternLen]==patternList[(i+1)%patternLen] && patternList[i%patternLen]==0)
            sum = sum + 1;
        else
            sum = 0;
        if(sum>=skipLimit)
        {
            patternList[newSkipPosition] = 1;
            return 0;
        }
    }

    return 1;
}


// This function checks if 'item' belongs to attack window 'atkWin'
// ** we have to see which instance of higher priority task belongs to atkWin
int CheckMembership(int *atkWin, int atkWinLen, int item)
{
    int i=0;

    for(i=0;i<atkWinLen;i++)
    {
        if(atkWin[i] == item)
            return i;
    }

    return -1;
}


/* ─────────────  CSV writers (use %s)  ───────────────────────── */
void SaveFinalCandidatesCSV(struct Message *c,int n){
    FILE *f=fopen("final_candidates.csv","w");
    fprintf(f,"CandidateID,Periodicity,InstanceIndex,Attackable,AtkWinLen,AtkWinCount\n");
    for(int i=0;i<n;i++)
        for(int j=0;j<c[i].count;j++)
            fprintf(f,"%s,%.3f,%d,%d,%d,%d\n",
                    c[i].ID,c[i].periodicity,
                    j,c[i].instances[j].attackable,
                    c[i].instances[j].atkWinLen,
                    c[i].instances[j].atkWinCount);
    fclose(f);
}
void SaveIDSummaryCSV(struct Message *c,int n){
    FILE *f=fopen("id_summary.csv","w");
    fprintf(f,"Identifier,Periodicity,MeanAtkWinLen,Attackable\n");
    for(int i=0;i<n;i++){
        long sum=0,flag=0;
        for(int j=0;j<c[i].count;j++){
            sum+=c[i].instances[j].atkWinLen;
            flag|=c[i].instances[j].attackable;
        }
        fprintf(f,"%s,%.4f,%.1f,%ld\n",
                c[i].ID,c[i].periodicity,
                sum/(double)c[i].count,flag);
    }
    fclose(f);
}

/* ─────────────  dynamic list (-i)  ─────────────────────────── */
#define MAX_ECU 64
char  dynIDs[MAX_ECU][IDLEN];
float dynPeriods[MAX_ECU];
int   dynSkip[MAX_ECU];
int   dynCount=0, useDynamic=0;

// void parse_id_list(char *csv){
//     char *tok=strtok(csv,",");
//     while(tok&&dynCount<MAX_ECU){
//         strncpy(dynIDs[dynCount++],tok,IDLEN); tok=strtok(NULL,",");
//     }
// }
void parse_id_list(char *csv)
{
    char *tok = strtok(csv, ",");
    while (tok && dynCount < MAX_ECU) {
        if (tok[0]!='0' || (tok[1]!='x' && tok[1]!='X'))  /* add 0x */
            snprintf(dynIDs[dynCount], IDLEN, "0x%s", tok);
        else
            strncpy(dynIDs[dynCount], tok, IDLEN);
        dynCount++;
        tok = strtok(NULL, ",");
    }
}

void fill_periods(void){
    for(int i=0;i<dynCount;i++){ dynPeriods[i]=0.05f; dynSkip[i]=2; }
    FILE *fp=fopen("periods.txt","r"); if(!fp) return;
    char sid[IDLEN]; float per;
    while(fscanf(fp,"%7s%f",sid,&per)==2)
        for(int i=0;i<dynCount;i++)
            if(strcmp(dynIDs[i],sid)==0) dynPeriods[i]=per;
    fclose(fp);
}

/* ─────────────  main  ──────────────────────────────────────── */
int main(int argc,char **argv)
{
    if(argc<2){ puts("usage: ./sched_attack <csv> [-i id1,id2]"); return 1; }
    char *csvFile=argv[1];

    int opt; while((opt=getopt(argc-1,argv+1,"i:"))!=-1)
        if(opt=='i'){ useDynamic=1; parse_id_list(optarg); }

    if(useDynamic){
        fill_periods();
        ECUIDsArr   = (const char**)dynIDs;
        ECUIDPeriodsArr  = dynPeriods;
        ctrlSkipLimitArr = dynSkip;
        ECUCountVar      = dynCount;
    }

    int i = 0, sum = 0, j = 0, k = 0, l = 0;
    int CANCount = 0, ifSkip = 0, insToSkipObf1 = 0, insToSkipObf2 = 0, initDectec = 0;
    float smallestPeriod = 0;

    srand(time(0));

    /* allocate and run */
    struct Message *traffic=NULL,*cand=calloc(ECUCountVar,sizeof(struct Message));
    CANCount = InitializeCANTraffic(&traffic,csvFile);
    printf("Loaded %d packets from CSV\n", CANCount);       /* ← ① */
    if (CANCount <= 0) { puts("Nothing to analyse – abort"); return 1; }
    InitializeECU(&cand);
    printf("First ECU ID: %s\n", cand[0].ID);               /* ← ② */
    printf("First packet ID: %s\n", traffic[0].ID);         /* ← ③ */

    while (l <= 10)
    {
        printf("\nAnalyzing the CAN traffic.......................");
        AnalyzeCANTraffic(traffic, CANCount, &cand);

        /* ---------- compute avg attack-window & label ------------- */
        for (i = 0; i < ECUCountVar; i++)
        {
            sum = 0;
            for (j = 0; j < cand[i].count; j++)
            {
                cand[i].instances[j].attackable =
                    (cand[i].instances[j].atkWinLen >= minAtkWinLen);
                sum += cand[i].instances[j].atkWinLen;
            }
            cand[i].atkWinLen = sum / cand[i].count;
        }

        /* ---------- print & sort instances ------------------------ */
        for (i = 0; i < ECUCountVar; i++)
        {
            InsSortByAtkWinLen(&cand[i].instances, 0, cand[i].count - 1);

            printf("\n Candidate ID = %s", cand[i].ID);
            printf("\n--------------------------------------------------");
            for (j = 0; j < cand[i].count; j++)
            {
                printf("\n %d: Instance = %d: attack win len = %d, attack win count = %d",
                    j, cand[i].instances[j].index,
                    cand[i].instances[j].atkWinLen,
                    cand[i].instances[j].atkWinCount);

                printf("\n Attack window:");
                for (k = 0; k < cand[i].instances[j].atkWinCount; k++)
                    printf("%d(instance=%d)  ",
                        cand[i].instances[j].atkWin[k],
                        cand[i].instances[j].insWin[k]);
            }
            printf("\n Pattern: ");
            for (j = 0; j < cand[i].count; j++)
                printf("%d ", cand[i].pattern[j]);
            printf("\n===========================================================================================");
        }

        /* ---------- obfuscation policies -------------------------- */
        printf("\n Obfuscation policy initiated....................");
        for (i = 0; i < ECUCountVar; i++)
        {
            ifSkip = 0; insToSkipObf1 = 0; insToSkipObf2 = 0; j = 0;

            printf("\nCandidate ID = %s", cand[i].ID);
            printf("\n Checking obfuscation 1");
            while (j < cand[i].count &&
                (!cand[i].instances[j].attackable ||
                !cand[i].pattern[cand[i].instances[j].index]))
                j++;

            printf("\n sorted order = %d", j);

            if (j < cand[i].count)
            {
                insToSkipObf1 = cand[i].instances[j].index;
                ifSkip = IfSkipPossible(cand[i].pattern, cand[i].count,
                                        cand[i].skipLimit, insToSkipObf1);
            }
            if (ifSkip) continue;     /* obf-1 succeeded */

            /* ------ obfuscation 2 --------------------------------- */
            printf("\n Checking obfuscation 2");
            for (j = 0; j < i && !ifSkip; j++)
            {
                insToSkipObf2 = CheckMembership(
                    cand[i].instances[insToSkipObf1].atkWin,
                    cand[i].instances[insToSkipObf1].atkWinCount,
                    id_to_long(cand[j].ID));

                if (insToSkipObf2 >= 0)
                    ifSkip = IfSkipPossible(cand[j].pattern, cand[j].count,
                                            ctrlSkipLimitArr[j], insToSkipObf2);
            }

            /* ------ obfuscation 3 --------------------------------- */
            if (!ifSkip)
            {
                printf("\n Checking obfuscation 3");
                for (k = i - 1; k >= 0; k--)
                    if (cand[i].periodicity != cand[k].periodicity) break;

                if (k != i - 1)
                {
                    k++;
                    if (cand[i].periodicity == cand[k].periodicity &&
                        CheckMembership(
                            cand[i].instances[insToSkipObf1].atkWin,
                            cand[i].instances[insToSkipObf1].atkWinCount,
                            id_to_long(cand[k].ID)) >= 0)
                    {
                        struct Message temp = cand[k];
                        cand[k] = cand[i];
                        cand[i] = temp;
                    }
                }
            }
        }
        l++;
    }

    SaveFinalCandidatesCSV(cand,ECUCountVar);
    SaveIDSummaryCSV(cand,ECUCountVar);
    free(cand); free(traffic);
    return 0;
}
