#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/aes.h>

#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#include "aes_locl.h" /* for u32 */
#include <assert.h>

/* 
    This file provides the synthetic benchmark for SpectreGuard. It
    splits execution into two sections.
    
    Work
        This section performs an algorithm that is moderately dependent
        on speculative execution for performance. We could have made
        this even more performance dependent on speculation, but the
        intention was to create something significantly noticeable during
        testing, not a worse-case scenario.
    
    Encrypt
        This section simply performs the AES encryption algorithm. It
        contains minimal conditional branches, so it does not rely
        heavily on speculative execution for performance.
    
    The argument passed in will change the percent of time the program
    spends in the Encrypt section.
        ex: ./benchmark 10
            This should spend 10% of execution time in the Encrypt
            section when running in native -no Spectre protection-
            mode.
    
    The intention of the benchmark is:
    1)  To show the effect of marking data in non-critical, and
        non-reliant on speculation for performance, sections as
        non-speculative.
    2)  To show how to use the current programmer interfaces to use
        SpectreGuard.
    
    The intention is not:
    1)  To show how to create a secure application with regards to
        non-speculative attacks.
*/



struct bounded_array
{
    volatile unsigned int length; // length of array
    char * data; // pointer to array
};



/*  sudo-random data used for the double array access. It was
    originally chosen as sudo-random to confuse the prefetcher, but
    since all of the data should be able to fit within the caches, this
    is probably not needed. Still, it needs to be something, so we left
    it as such.
*/
unsigned int random_data[] = {1357,
    721,1204,1203,236,959,444,1131,433,968,224,862,1231,271,531,78,954,1216,1633,417,272,1612,1583,1580,706,750,504,332,905,1328,1449,1527,285,1395,212,1476,1383,1476,1099,329,476,
    18,1268,1491,1535,1638,1476,1541,1091,1175,1140,1215,977,146,110,1107,1398,565,1275,672,967,874,198,1306,620,1677,1671,1047,267,88,360,1620,1125,548,1245,559,885,961,1369,165,1319,
    1563,120,703,316,1101,73,58,1363,713,972,698,986,1395,827,1429,63,1680,287,260,859,149,765,527,428,1164,1047,779,1591,1352,1486,390,1394,1297,1167,1673,177,1196,843,227,580,
    1064,839,1280,453,1508,1684,462,1100,235,361,1395,1522,990,1501,1081,1293,488,88,112,514,659,482,55,799,1192,904,148,1434,480,1587,554,1108,655,6,1300,1615,1311,1017,366,677,
    242,1468,194,296,168,1023,148,465,891,202,1188,574,1474,284,1345,1298,1448,1316,1693,1115,1024,475,752,117,1327,65,1364,663,1290,1684,1164,1599,214,805,1674,325,719,721,376,272,
    327,71,1025,1370,858,472,1297,1027,1070,771,1240,349,850,461,6,1010,1582,605,140,929,66,1385,1091,579,70,1143,1579,973,464,270,1653,1487,337,1418,988,334,1421,728,98,1364,
    43,1270,373,113,918,377,89,996,229,137,1160,1381,334,1576,1367,1392,1618,1449,607,977,1605,834,794,272,448,630,458,208,426,279,850,241,34,496,22,956,555,1099,141,153,
    458,1571,350,327,35,215,1152,1296,1182,1609,1280,896,685,1653,322,229,233,657,533,1554,249,305,1628,1626,1061,85,16,730,850,425,963,543,1598,992,1033,1603,212,1489,526,854,
    729,20,198,588,536,1082,1693,1332,1380,1523,1641,1579,249,1642,1099,1249,85,392,1243,1386,1574,1328,978,1316,1507,1387,1152,294,1520,861,457,620,930,194,322,1089,886,1210,806,574,
    413,926,986,104,1510,352,1535,411,862,1294,1079,188,982,418,12,866,237,1166,1165,1519,401,714,581,825,826,15,1648,1525,766,1635,261,89,121,654,908,1643,1487,686,1594,1116,
    223,1373,1618,186,1033,1678,1536,78,743,835,1162,54,1120,1308,779,1532,1532,216,12,411,1656,222,102,1489,1449,972,71,823,1521,411,88,400,920,1444,961,12,190,216,627,722,
    662,1468,1658,1527,269,232,566,688,1233,614,1683,496,351,11,203,878,485,838,667,1318,863,336,1418,1680,891,1358,723,1230,146,1483,989,1547,1527,928,404,1041,723,1172,572,1144,
    1033,255,189,993,1259,1007,1550,683,1613,1394,152,1125,164,1500,1404,1496,591,1153,1696,108,119,310,702,1410,568,583,1370,1674,1477,572,143,276,385,623,1224,148,1409,1526,454,55,
    72,1674,688,1147,1676,1055,275,86,352,585,416,351,1682,513,224,114,1638,1276,1057,602,1623,616,422,470,1681,857,1298,503,8,1421,365,394,1062,991,1431,529,215,1317,1154,932,
    499,1294,1097,54,1158,1112,1220,1183,224,1290,572,1511,613,94,162,509,1023,1134,866,695,1097,1263,1317,1343,1470,351,14,1691,1438,507,8,157,1694,563,1272,1306,1051,1025,445,434,
    1187,567,130,1419,763,1396,416,1022,42,1460,89,141,1660,1,178,1,1344,328,678,417,286,64,188,590,1249,1303,1296,826,543,969,1657,296,387,117,630,388,944,491,248,1044,
    516,121,191,474,28,474,825,1009,76,1381,1002,946,333,445,1438,376,1551,37,1155,1551,1623,42,483,1427,737,884,1249,959,1007,1529,1340,128,1324,1148,1038,1151,1640,1516,1120,957,
    241,628,580,813,104,1597,1591,1160,867,1310,737,143,1087,1407,913,1370,642,1209,714,1560,802,827,205,68,304,1045,908,320,899,1297,27,659,1244,1253,190,691,1605,423,1632,1006,
    1356,1589,1012,559,1566,758,1347,1112,1563,537,1387,49,1428,588,1202,280,141,1525,997,60,1182,861,215,251,622,1389,820,990,1110,1405,1357,109,1162,1301,172,137,1629,894,371,1683,
    1573,31,32,1427,1082,491,156,1294,467,1505,207,1571,751,208,206,61,456,713,1682,1350,471,436,90,1423,317,1654,884,47,1509,565,988,157,1230,927,100,1679,1629,322,677,199,
    790,1520,1469,1346,1506,1361,711,1295,1032,129,1477,498,682,503,1599,288,916,698,594,152,1512,934,574,1190,550,1492,485,1297,1278,877,1097,1002,1523,993,1552,1093,654,590,510,597,
    1321,466,362,692,660,580,266,1282,717,1370,1453,1240,738,1608,1395,762,1494,231,705,22,1384,599,483,1637,560,1114,905,1629,110,1208,1423,1431,302,1053,53,627,386,1066,369,256,
    1396,72,1592,165,389,683,37,761,1549,1091,1253,870,1039,693,788,993,1541,588,386,335,515,232,1119,631,1,714,1238,1444,766,1144,1304,407,41,845,911,853,602,1362,812,861,
    1334,1115,1672,483,708,874,871,1291,665,387,1026,1483,1092,719,117,272,883,344,826,1181,1047,775,620,330,393,1570,129,1230,146,486,1272,851,1590,493,600,654,445,192,256,1573,
    494,1370,873,1208,1111,1353,31,1511,652,1102,101,637,1447,1419,405,804,526,658,745,1100,1561,636,1687,652,604,167,342,1081,350,387,1555,151,602,704,1676,677,398,1523,702,1656,
    707,782,823,1084,1652,1192,876,563,284,1278,1650,1254,457,750,249,590,1408,1428,1508,1400,717,729,534,59,1621,1559,752,684,1449,645,474,391,703,1105,318,1477,1126,639,719,599,
    438,372,62,1428,648,105,333,1052,715,1565,479,1441,1011,479,351,1368,1428,1207,1189,645,392,1071,460,738,772,1286,26,1119,374,1262,1640,846,1221,702,1009,1390,1559,1228,76,701,
    1239,14,738,564,245,1342,1519,1610,1327,882,431,1127,1649,149,46,478,349,829,1142,132,634,1043,961,303,1071,888,528,877,1257,658,828,876,637,554,1534,322,1284,538,756,53,
    974,852,596,569,1050,1169,1493,397,1254,485,98,274,1118,1438,323,1432,1548,1679,1223,960,658,740,1306,42,442,206,407,1096,1244,860,1255,1591,1600,257,590,643,1150,1552,674,1305,
    579,546,54,158,1471,1161,747,999,574,411,1533,863,1262,779,431,1240,125,1368,244,366,1127,1165,1241,691,1373,852,1440,701,87,1637,503,871,1438,704,130,1028,98,1433,192,488,
    334,5,356,1303,655,713,1166,1073,936,471,1301,250,1538,434,746,647,757,214,224,863,750,906,306,1333,1618,642,630,134,1092,1430,1268,1258,103,1046,889,1589,251,1153,928,194,
    1680,1558,1151,1375,652,974,274,992,16,760,630,999,296,1200,1085,22,85,488,1325,1458,37,92,1055,573,338,1601,920,1543,595,645,15,444,870,1286,4,923,358,1393,686,1518,
    1611,1430,201,1541,1659,781,318,968,103,304,422,440,517,30,1273,1276,193,521,1040,576,399,1192,1698,1373,1020,557,348,806,1046,607,67,1657,1338,70,1013,193,324,489,957,816,
    1308,1141,192,1366,990,796,558,236,1200,1688,1005,1588,151,800,1428,420,612,1162,61,1316,1181,128,322,1166,1369,595,445,681,1585,733,1459,917,282,22,1381,243,472,1050,288,638,
    966,1332,412,124,951,1088,9,978,93,166,249,1501,813,379,548,1274,124,242,272,379,1168,383,11,539,492,95,880,339,91,287,1018,1346,1550,102,1136,452,1120,219,795,314,
    666,1593,1455,322,1379,394,138,336,650,303,953,195,1443,102,204,952,133,1118,289,17,1346,969,559,1608,1048,1611,474,1597,1638,894,237,678,97,365,985,1132,939,46,558,141,
    938,355,650,128,1194,767,284,827,1223,4,725,1327,233,14,1373,1539,1552,23,1351,100,855,267,1561,260,15,531,718,1638,1004,550,1561,1637,1030,663,1528,77,587,1236,852,815,
    14,605,29,1091,183,1080,911,942,327,26,1335,131,1423,27,1406,543,39,653,724,780,292,703,1171,1105,583,1686,398,1632,85,1412,1260,1133,349,1259,26,1050,463,916,1462,701,
    760,336,408,1222,1415,94,1277,303,1687,1583,1666,1302,90,1605,301,1249,1311,1544,238,1507,970,1238,832,1538,1536,64,870,509,1689,1615,1248,825,1425,1099,1156,166,1057,593,464,898,
    815,101,1516,331,1634,301,946,638,1585,808,951,1265,1510,1594,696,1107,669,31,350,1231,406,317,1629,1060,1515,313,509,1126,444,1029,182,1615,44,1536,1051,1154,1488,411,507,};


struct bounded_array random_dat = {
    1024,
    (char *)random_data
};


/* The data that we will perform work on, and then encrypt. */
char plain_text_orig_data[] =   "oDFV2O1aP136YnmEbhZJLMizLukPQF3Ir6kzrYGMOm9M822cFsuLftYMulqTzNwmhvoTkUr7mFwm0r8w2t51ccg2qgRhdWrI5ldwsnRZXoXoogHLUYbNMQPn8Pc4SPVRckc1XtQVAoIFSaBrOX3WBl27GZQfqTUROjIrSwlErkwevuIXQfby8WtMRbw8f0RrvJCytHaJfWyD9rC0VMCMFl4gZstTw0WxxBvAEQEhtBdJkJKOEw1xUo9MyiLj77QD14XSzx2p9wFEpPTbP96X69Mz628IaGgmGbKO06uFesKISWF4qltlIe74Jm00kZpeXCx7uZQ02VGQ3vLPSanJUBv0FYVMbl2VoARBo1D0IAwYvk35fLR4qXUinVgoL8NxhaaNi6Al6zww23kBSlzXZimSkkG0V9mmjArlOyE5N6DR0C2n9R6jEtsUQejADev21cWPE742mQc8q50u8B5X5QWYiPsZVz4VlMnC0aNDRH7gQMz4gCfuEfd14sm4Kl7TdNGHw0VzrxaFARKR1T6kih3RgeBCQGYvIJiP9oWQQvXf0WkoL289SrwOYA5lj8ArAH3ftM15K4ih3UrXVfZHvE031bqwTueRZQPTGp7psY5jBNGs5G8bUROxYtUwS63lkJTj7IuvIUaTIgJvxQHrMUSnN86aG6uMUlNZCFF8lJamsDtLAU5WlXs5aWS2ckwmo0BECJxkZwg8FiPmY2A4EPrmcKnLIj0DHHmbelAV57KmPmRk9q3LeFZeNJvranJU3FDioc5rSAxT16M5rDlZlxdLANByfz6jaaVa3CcqTGFfS5F0ZHcZlDCEy4fzLQtwDACfQAoiUAOvmfI01q89U1fNqIBcbuXi8AZwcos19bJCpOZfaTkBEldeC2EmTLVLZZ6XhZWBJf6iKL2sJriGPfJY6NT67LOit0cvPs8N8o2v9XP7HSRw7RPm5h3GSeVGbcftzQ4VgEefEIlu4QWgoMqRsnASzEhAS0TPk4AUC63ieNwRjwBerK7PA60Oq9tyRfUfqWXlvCfqV8JOUDo9hzxxopC4Bk0HtjPZ21KyPqQD2AFGVSWcucK4ZL3eYed1R9yG2XWDUfpT5Z8pFNX59X9SAlyjob28IHayBhVmVlmJDFTVS7vcsVqACSetqJCexJ8kkBO1eCI1x67LjztTT2N7o4gmb8zunYutnHpIO9OFdVuqv1taRrcCFBhNrhpeBME7n94QQnTK2zJ7grqhEm1ZXLkO235sCIDXnSmkiCsvvNiYEfVyksi3bjZFlNLIgLorrdR3ykjFWAyJxkotmGCIxLQ1ykGJU8wDLoTnKD21z6IHm9YNl3HNLPEHIzOMdJuYwazUb1ih00RNsr9OYcSPxy7s0xrpt3sJZ44DWtGYwN84OY5eCHhyP2UdiV4Otlqtbj3seC2yCJ9hznVO67yNHsp07vQgIUXGZSbX5zzTRLrkHrDAVexrKElHrafqRgWwnzibtlvo8cd6jknGbIzXKypEAREYrCzLBusH3A7A8xMc6Gox4JEJxpZ22Ui5MuFA5fQt9xNwKSJmsZPENe55wjcLg58MWZey8cbiA3LpqK2lPRC7mvBpVvIb0dxD";
    
struct bounded_array plain_text_orig = {
    1600,
    plain_text_orig_data
};


char plain_in_data[8192];
struct bounded_array plain_in = {
    8192,
    plain_in_data
};





/*  The buffer that will contain the secret key. This is allocated
    differently if the buffer will be protected by SpectreGuard
*/
#define ONE_PAGE 4096
#ifdef WB_ON_RETIRE
#  define MAP_WB_ON_RETIRE 0x200000
    static AES_KEY * alloc_key( void )
    {
        AES_KEY * my_key_space = mmap(NULL, ONE_PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_WB_ON_RETIRE, -1, 0);
        memset(my_key_space, 0, ONE_PAGE);
        return my_key_space;
    }
#else
    static AES_KEY * alloc_key( void )
    {
        AES_KEY * my_key_space = mmap(NULL, ONE_PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memset(my_key_space, 0, ONE_PAGE);
        return my_key_space;
    }
#endif




/* The access functions that potentially contain Spectre gadgets. */
static inline char get_byte( struct bounded_array * ba, unsigned int offset )
{
    if( offset < ba->length )
    {
        return ba->data[offset];
    }
    
    return 0;
}

static inline int get_int( struct bounded_array * ba, unsigned int offset )
{
    if( offset < ba->length )
    {
        return ((int *)(ba->data))[offset];
    }
    
    return 0;
}

static inline void set_byte( struct bounded_array * ba, unsigned int offset, char value )
{
    if( offset < ba->length )
    {
        ba->data[offset] = value;
    }
}

static const u32 Te0[256] = {
    0xc66363a5U, 0xf87c7c84U, 0xee777799U, 0xf67b7b8dU,
    0xfff2f20dU, 0xd66b6bbdU, 0xde6f6fb1U, 0x91c5c554U,
    0x60303050U, 0x02010103U, 0xce6767a9U, 0x562b2b7dU,
    0xe7fefe19U, 0xb5d7d762U, 0x4dababe6U, 0xec76769aU,
    0x8fcaca45U, 0x1f82829dU, 0x89c9c940U, 0xfa7d7d87U,
    0xeffafa15U, 0xb25959ebU, 0x8e4747c9U, 0xfbf0f00bU,
    0x41adadecU, 0xb3d4d467U, 0x5fa2a2fdU, 0x45afafeaU,
    0x239c9cbfU, 0x53a4a4f7U, 0xe4727296U, 0x9bc0c05bU,
    0x75b7b7c2U, 0xe1fdfd1cU, 0x3d9393aeU, 0x4c26266aU,
    0x6c36365aU, 0x7e3f3f41U, 0xf5f7f702U, 0x83cccc4fU,
    0x6834345cU, 0x51a5a5f4U, 0xd1e5e534U, 0xf9f1f108U,
    0xe2717193U, 0xabd8d873U, 0x62313153U, 0x2a15153fU,
    0x0804040cU, 0x95c7c752U, 0x46232365U, 0x9dc3c35eU,
    0x30181828U, 0x379696a1U, 0x0a05050fU, 0x2f9a9ab5U,
    0x0e070709U, 0x24121236U, 0x1b80809bU, 0xdfe2e23dU,
    0xcdebeb26U, 0x4e272769U, 0x7fb2b2cdU, 0xea75759fU,
    0x1209091bU, 0x1d83839eU, 0x582c2c74U, 0x341a1a2eU,
    0x361b1b2dU, 0xdc6e6eb2U, 0xb45a5aeeU, 0x5ba0a0fbU,
    0xa45252f6U, 0x763b3b4dU, 0xb7d6d661U, 0x7db3b3ceU,
    0x5229297bU, 0xdde3e33eU, 0x5e2f2f71U, 0x13848497U,
    0xa65353f5U, 0xb9d1d168U, 0x00000000U, 0xc1eded2cU,
    0x40202060U, 0xe3fcfc1fU, 0x79b1b1c8U, 0xb65b5bedU,
    0xd46a6abeU, 0x8dcbcb46U, 0x67bebed9U, 0x7239394bU,
    0x944a4adeU, 0x984c4cd4U, 0xb05858e8U, 0x85cfcf4aU,
    0xbbd0d06bU, 0xc5efef2aU, 0x4faaaae5U, 0xedfbfb16U,
    0x864343c5U, 0x9a4d4dd7U, 0x66333355U, 0x11858594U,
    0x8a4545cfU, 0xe9f9f910U, 0x04020206U, 0xfe7f7f81U,
    0xa05050f0U, 0x783c3c44U, 0x259f9fbaU, 0x4ba8a8e3U,
    0xa25151f3U, 0x5da3a3feU, 0x804040c0U, 0x058f8f8aU,
    0x3f9292adU, 0x219d9dbcU, 0x70383848U, 0xf1f5f504U,
    0x63bcbcdfU, 0x77b6b6c1U, 0xafdada75U, 0x42212163U,
    0x20101030U, 0xe5ffff1aU, 0xfdf3f30eU, 0xbfd2d26dU,
    0x81cdcd4cU, 0x180c0c14U, 0x26131335U, 0xc3ecec2fU,
    0xbe5f5fe1U, 0x359797a2U, 0x884444ccU, 0x2e171739U,
    0x93c4c457U, 0x55a7a7f2U, 0xfc7e7e82U, 0x7a3d3d47U,
    0xc86464acU, 0xba5d5de7U, 0x3219192bU, 0xe6737395U,
    0xc06060a0U, 0x19818198U, 0x9e4f4fd1U, 0xa3dcdc7fU,
    0x44222266U, 0x542a2a7eU, 0x3b9090abU, 0x0b888883U,
    0x8c4646caU, 0xc7eeee29U, 0x6bb8b8d3U, 0x2814143cU,
    0xa7dede79U, 0xbc5e5ee2U, 0x160b0b1dU, 0xaddbdb76U,
    0xdbe0e03bU, 0x64323256U, 0x743a3a4eU, 0x140a0a1eU,
    0x924949dbU, 0x0c06060aU, 0x4824246cU, 0xb85c5ce4U,
    0x9fc2c25dU, 0xbdd3d36eU, 0x43acacefU, 0xc46262a6U,
    0x399191a8U, 0x319595a4U, 0xd3e4e437U, 0xf279798bU,
    0xd5e7e732U, 0x8bc8c843U, 0x6e373759U, 0xda6d6db7U,
    0x018d8d8cU, 0xb1d5d564U, 0x9c4e4ed2U, 0x49a9a9e0U,
    0xd86c6cb4U, 0xac5656faU, 0xf3f4f407U, 0xcfeaea25U,
    0xca6565afU, 0xf47a7a8eU, 0x47aeaee9U, 0x10080818U,
    0x6fbabad5U, 0xf0787888U, 0x4a25256fU, 0x5c2e2e72U,
    0x381c1c24U, 0x57a6a6f1U, 0x73b4b4c7U, 0x97c6c651U,
    0xcbe8e823U, 0xa1dddd7cU, 0xe874749cU, 0x3e1f1f21U,
    0x964b4bddU, 0x61bdbddcU, 0x0d8b8b86U, 0x0f8a8a85U,
    0xe0707090U, 0x7c3e3e42U, 0x71b5b5c4U, 0xcc6666aaU,
    0x904848d8U, 0x06030305U, 0xf7f6f601U, 0x1c0e0e12U,
    0xc26161a3U, 0x6a35355fU, 0xae5757f9U, 0x69b9b9d0U,
    0x17868691U, 0x99c1c158U, 0x3a1d1d27U, 0x279e9eb9U,
    0xd9e1e138U, 0xebf8f813U, 0x2b9898b3U, 0x22111133U,
    0xd26969bbU, 0xa9d9d970U, 0x078e8e89U, 0x339494a7U,
    0x2d9b9bb6U, 0x3c1e1e22U, 0x15878792U, 0xc9e9e920U,
    0x87cece49U, 0xaa5555ffU, 0x50282878U, 0xa5dfdf7aU,
    0x038c8c8fU, 0x59a1a1f8U, 0x09898980U, 0x1a0d0d17U,
    0x65bfbfdaU, 0xd7e6e631U, 0x844242c6U, 0xd06868b8U,
    0x824141c3U, 0x299999b0U, 0x5a2d2d77U, 0x1e0f0f11U,
    0x7bb0b0cbU, 0xa85454fcU, 0x6dbbbbd6U, 0x2c16163aU,
};
static const u32 Te1[256] = {
    0xa5c66363U, 0x84f87c7cU, 0x99ee7777U, 0x8df67b7bU,
    0x0dfff2f2U, 0xbdd66b6bU, 0xb1de6f6fU, 0x5491c5c5U,
    0x50603030U, 0x03020101U, 0xa9ce6767U, 0x7d562b2bU,
    0x19e7fefeU, 0x62b5d7d7U, 0xe64dababU, 0x9aec7676U,
    0x458fcacaU, 0x9d1f8282U, 0x4089c9c9U, 0x87fa7d7dU,
    0x15effafaU, 0xebb25959U, 0xc98e4747U, 0x0bfbf0f0U,
    0xec41adadU, 0x67b3d4d4U, 0xfd5fa2a2U, 0xea45afafU,
    0xbf239c9cU, 0xf753a4a4U, 0x96e47272U, 0x5b9bc0c0U,
    0xc275b7b7U, 0x1ce1fdfdU, 0xae3d9393U, 0x6a4c2626U,
    0x5a6c3636U, 0x417e3f3fU, 0x02f5f7f7U, 0x4f83ccccU,
    0x5c683434U, 0xf451a5a5U, 0x34d1e5e5U, 0x08f9f1f1U,
    0x93e27171U, 0x73abd8d8U, 0x53623131U, 0x3f2a1515U,
    0x0c080404U, 0x5295c7c7U, 0x65462323U, 0x5e9dc3c3U,
    0x28301818U, 0xa1379696U, 0x0f0a0505U, 0xb52f9a9aU,
    0x090e0707U, 0x36241212U, 0x9b1b8080U, 0x3ddfe2e2U,
    0x26cdebebU, 0x694e2727U, 0xcd7fb2b2U, 0x9fea7575U,
    0x1b120909U, 0x9e1d8383U, 0x74582c2cU, 0x2e341a1aU,
    0x2d361b1bU, 0xb2dc6e6eU, 0xeeb45a5aU, 0xfb5ba0a0U,
    0xf6a45252U, 0x4d763b3bU, 0x61b7d6d6U, 0xce7db3b3U,
    0x7b522929U, 0x3edde3e3U, 0x715e2f2fU, 0x97138484U,
    0xf5a65353U, 0x68b9d1d1U, 0x00000000U, 0x2cc1ededU,
    0x60402020U, 0x1fe3fcfcU, 0xc879b1b1U, 0xedb65b5bU,
    0xbed46a6aU, 0x468dcbcbU, 0xd967bebeU, 0x4b723939U,
    0xde944a4aU, 0xd4984c4cU, 0xe8b05858U, 0x4a85cfcfU,
    0x6bbbd0d0U, 0x2ac5efefU, 0xe54faaaaU, 0x16edfbfbU,
    0xc5864343U, 0xd79a4d4dU, 0x55663333U, 0x94118585U,
    0xcf8a4545U, 0x10e9f9f9U, 0x06040202U, 0x81fe7f7fU,
    0xf0a05050U, 0x44783c3cU, 0xba259f9fU, 0xe34ba8a8U,
    0xf3a25151U, 0xfe5da3a3U, 0xc0804040U, 0x8a058f8fU,
    0xad3f9292U, 0xbc219d9dU, 0x48703838U, 0x04f1f5f5U,
    0xdf63bcbcU, 0xc177b6b6U, 0x75afdadaU, 0x63422121U,
    0x30201010U, 0x1ae5ffffU, 0x0efdf3f3U, 0x6dbfd2d2U,
    0x4c81cdcdU, 0x14180c0cU, 0x35261313U, 0x2fc3ececU,
    0xe1be5f5fU, 0xa2359797U, 0xcc884444U, 0x392e1717U,
    0x5793c4c4U, 0xf255a7a7U, 0x82fc7e7eU, 0x477a3d3dU,
    0xacc86464U, 0xe7ba5d5dU, 0x2b321919U, 0x95e67373U,
    0xa0c06060U, 0x98198181U, 0xd19e4f4fU, 0x7fa3dcdcU,
    0x66442222U, 0x7e542a2aU, 0xab3b9090U, 0x830b8888U,
    0xca8c4646U, 0x29c7eeeeU, 0xd36bb8b8U, 0x3c281414U,
    0x79a7dedeU, 0xe2bc5e5eU, 0x1d160b0bU, 0x76addbdbU,
    0x3bdbe0e0U, 0x56643232U, 0x4e743a3aU, 0x1e140a0aU,
    0xdb924949U, 0x0a0c0606U, 0x6c482424U, 0xe4b85c5cU,
    0x5d9fc2c2U, 0x6ebdd3d3U, 0xef43acacU, 0xa6c46262U,
    0xa8399191U, 0xa4319595U, 0x37d3e4e4U, 0x8bf27979U,
    0x32d5e7e7U, 0x438bc8c8U, 0x596e3737U, 0xb7da6d6dU,
    0x8c018d8dU, 0x64b1d5d5U, 0xd29c4e4eU, 0xe049a9a9U,
    0xb4d86c6cU, 0xfaac5656U, 0x07f3f4f4U, 0x25cfeaeaU,
    0xafca6565U, 0x8ef47a7aU, 0xe947aeaeU, 0x18100808U,
    0xd56fbabaU, 0x88f07878U, 0x6f4a2525U, 0x725c2e2eU,
    0x24381c1cU, 0xf157a6a6U, 0xc773b4b4U, 0x5197c6c6U,
    0x23cbe8e8U, 0x7ca1ddddU, 0x9ce87474U, 0x213e1f1fU,
    0xdd964b4bU, 0xdc61bdbdU, 0x860d8b8bU, 0x850f8a8aU,
    0x90e07070U, 0x427c3e3eU, 0xc471b5b5U, 0xaacc6666U,
    0xd8904848U, 0x05060303U, 0x01f7f6f6U, 0x121c0e0eU,
    0xa3c26161U, 0x5f6a3535U, 0xf9ae5757U, 0xd069b9b9U,
    0x91178686U, 0x5899c1c1U, 0x273a1d1dU, 0xb9279e9eU,
    0x38d9e1e1U, 0x13ebf8f8U, 0xb32b9898U, 0x33221111U,
    0xbbd26969U, 0x70a9d9d9U, 0x89078e8eU, 0xa7339494U,
    0xb62d9b9bU, 0x223c1e1eU, 0x92158787U, 0x20c9e9e9U,
    0x4987ceceU, 0xffaa5555U, 0x78502828U, 0x7aa5dfdfU,
    0x8f038c8cU, 0xf859a1a1U, 0x80098989U, 0x171a0d0dU,
    0xda65bfbfU, 0x31d7e6e6U, 0xc6844242U, 0xb8d06868U,
    0xc3824141U, 0xb0299999U, 0x775a2d2dU, 0x111e0f0fU,
    0xcb7bb0b0U, 0xfca85454U, 0xd66dbbbbU, 0x3a2c1616U,
};
static const u32 Te2[256] = {
    0x63a5c663U, 0x7c84f87cU, 0x7799ee77U, 0x7b8df67bU,
    0xf20dfff2U, 0x6bbdd66bU, 0x6fb1de6fU, 0xc55491c5U,
    0x30506030U, 0x01030201U, 0x67a9ce67U, 0x2b7d562bU,
    0xfe19e7feU, 0xd762b5d7U, 0xabe64dabU, 0x769aec76U,
    0xca458fcaU, 0x829d1f82U, 0xc94089c9U, 0x7d87fa7dU,
    0xfa15effaU, 0x59ebb259U, 0x47c98e47U, 0xf00bfbf0U,
    0xadec41adU, 0xd467b3d4U, 0xa2fd5fa2U, 0xafea45afU,
    0x9cbf239cU, 0xa4f753a4U, 0x7296e472U, 0xc05b9bc0U,
    0xb7c275b7U, 0xfd1ce1fdU, 0x93ae3d93U, 0x266a4c26U,
    0x365a6c36U, 0x3f417e3fU, 0xf702f5f7U, 0xcc4f83ccU,
    0x345c6834U, 0xa5f451a5U, 0xe534d1e5U, 0xf108f9f1U,
    0x7193e271U, 0xd873abd8U, 0x31536231U, 0x153f2a15U,
    0x040c0804U, 0xc75295c7U, 0x23654623U, 0xc35e9dc3U,
    0x18283018U, 0x96a13796U, 0x050f0a05U, 0x9ab52f9aU,
    0x07090e07U, 0x12362412U, 0x809b1b80U, 0xe23ddfe2U,
    0xeb26cdebU, 0x27694e27U, 0xb2cd7fb2U, 0x759fea75U,
    0x091b1209U, 0x839e1d83U, 0x2c74582cU, 0x1a2e341aU,
    0x1b2d361bU, 0x6eb2dc6eU, 0x5aeeb45aU, 0xa0fb5ba0U,
    0x52f6a452U, 0x3b4d763bU, 0xd661b7d6U, 0xb3ce7db3U,
    0x297b5229U, 0xe33edde3U, 0x2f715e2fU, 0x84971384U,
    0x53f5a653U, 0xd168b9d1U, 0x00000000U, 0xed2cc1edU,
    0x20604020U, 0xfc1fe3fcU, 0xb1c879b1U, 0x5bedb65bU,
    0x6abed46aU, 0xcb468dcbU, 0xbed967beU, 0x394b7239U,
    0x4ade944aU, 0x4cd4984cU, 0x58e8b058U, 0xcf4a85cfU,
    0xd06bbbd0U, 0xef2ac5efU, 0xaae54faaU, 0xfb16edfbU,
    0x43c58643U, 0x4dd79a4dU, 0x33556633U, 0x85941185U,
    0x45cf8a45U, 0xf910e9f9U, 0x02060402U, 0x7f81fe7fU,
    0x50f0a050U, 0x3c44783cU, 0x9fba259fU, 0xa8e34ba8U,
    0x51f3a251U, 0xa3fe5da3U, 0x40c08040U, 0x8f8a058fU,
    0x92ad3f92U, 0x9dbc219dU, 0x38487038U, 0xf504f1f5U,
    0xbcdf63bcU, 0xb6c177b6U, 0xda75afdaU, 0x21634221U,
    0x10302010U, 0xff1ae5ffU, 0xf30efdf3U, 0xd26dbfd2U,
    0xcd4c81cdU, 0x0c14180cU, 0x13352613U, 0xec2fc3ecU,
    0x5fe1be5fU, 0x97a23597U, 0x44cc8844U, 0x17392e17U,
    0xc45793c4U, 0xa7f255a7U, 0x7e82fc7eU, 0x3d477a3dU,
    0x64acc864U, 0x5de7ba5dU, 0x192b3219U, 0x7395e673U,
    0x60a0c060U, 0x81981981U, 0x4fd19e4fU, 0xdc7fa3dcU,
    0x22664422U, 0x2a7e542aU, 0x90ab3b90U, 0x88830b88U,
    0x46ca8c46U, 0xee29c7eeU, 0xb8d36bb8U, 0x143c2814U,
    0xde79a7deU, 0x5ee2bc5eU, 0x0b1d160bU, 0xdb76addbU,
    0xe03bdbe0U, 0x32566432U, 0x3a4e743aU, 0x0a1e140aU,
    0x49db9249U, 0x060a0c06U, 0x246c4824U, 0x5ce4b85cU,
    0xc25d9fc2U, 0xd36ebdd3U, 0xacef43acU, 0x62a6c462U,
    0x91a83991U, 0x95a43195U, 0xe437d3e4U, 0x798bf279U,
    0xe732d5e7U, 0xc8438bc8U, 0x37596e37U, 0x6db7da6dU,
    0x8d8c018dU, 0xd564b1d5U, 0x4ed29c4eU, 0xa9e049a9U,
    0x6cb4d86cU, 0x56faac56U, 0xf407f3f4U, 0xea25cfeaU,
    0x65afca65U, 0x7a8ef47aU, 0xaee947aeU, 0x08181008U,
    0xbad56fbaU, 0x7888f078U, 0x256f4a25U, 0x2e725c2eU,
    0x1c24381cU, 0xa6f157a6U, 0xb4c773b4U, 0xc65197c6U,
    0xe823cbe8U, 0xdd7ca1ddU, 0x749ce874U, 0x1f213e1fU,
    0x4bdd964bU, 0xbddc61bdU, 0x8b860d8bU, 0x8a850f8aU,
    0x7090e070U, 0x3e427c3eU, 0xb5c471b5U, 0x66aacc66U,
    0x48d89048U, 0x03050603U, 0xf601f7f6U, 0x0e121c0eU,
    0x61a3c261U, 0x355f6a35U, 0x57f9ae57U, 0xb9d069b9U,
    0x86911786U, 0xc15899c1U, 0x1d273a1dU, 0x9eb9279eU,
    0xe138d9e1U, 0xf813ebf8U, 0x98b32b98U, 0x11332211U,
    0x69bbd269U, 0xd970a9d9U, 0x8e89078eU, 0x94a73394U,
    0x9bb62d9bU, 0x1e223c1eU, 0x87921587U, 0xe920c9e9U,
    0xce4987ceU, 0x55ffaa55U, 0x28785028U, 0xdf7aa5dfU,
    0x8c8f038cU, 0xa1f859a1U, 0x89800989U, 0x0d171a0dU,
    0xbfda65bfU, 0xe631d7e6U, 0x42c68442U, 0x68b8d068U,
    0x41c38241U, 0x99b02999U, 0x2d775a2dU, 0x0f111e0fU,
    0xb0cb7bb0U, 0x54fca854U, 0xbbd66dbbU, 0x163a2c16U,
};
static const u32 Te3[256] = {
    0x6363a5c6U, 0x7c7c84f8U, 0x777799eeU, 0x7b7b8df6U,
    0xf2f20dffU, 0x6b6bbdd6U, 0x6f6fb1deU, 0xc5c55491U,
    0x30305060U, 0x01010302U, 0x6767a9ceU, 0x2b2b7d56U,
    0xfefe19e7U, 0xd7d762b5U, 0xababe64dU, 0x76769aecU,
    0xcaca458fU, 0x82829d1fU, 0xc9c94089U, 0x7d7d87faU,
    0xfafa15efU, 0x5959ebb2U, 0x4747c98eU, 0xf0f00bfbU,
    0xadadec41U, 0xd4d467b3U, 0xa2a2fd5fU, 0xafafea45U,
    0x9c9cbf23U, 0xa4a4f753U, 0x727296e4U, 0xc0c05b9bU,
    0xb7b7c275U, 0xfdfd1ce1U, 0x9393ae3dU, 0x26266a4cU,
    0x36365a6cU, 0x3f3f417eU, 0xf7f702f5U, 0xcccc4f83U,
    0x34345c68U, 0xa5a5f451U, 0xe5e534d1U, 0xf1f108f9U,
    0x717193e2U, 0xd8d873abU, 0x31315362U, 0x15153f2aU,
    0x04040c08U, 0xc7c75295U, 0x23236546U, 0xc3c35e9dU,
    0x18182830U, 0x9696a137U, 0x05050f0aU, 0x9a9ab52fU,
    0x0707090eU, 0x12123624U, 0x80809b1bU, 0xe2e23ddfU,
    0xebeb26cdU, 0x2727694eU, 0xb2b2cd7fU, 0x75759feaU,
    0x09091b12U, 0x83839e1dU, 0x2c2c7458U, 0x1a1a2e34U,
    0x1b1b2d36U, 0x6e6eb2dcU, 0x5a5aeeb4U, 0xa0a0fb5bU,
    0x5252f6a4U, 0x3b3b4d76U, 0xd6d661b7U, 0xb3b3ce7dU,
    0x29297b52U, 0xe3e33eddU, 0x2f2f715eU, 0x84849713U,
    0x5353f5a6U, 0xd1d168b9U, 0x00000000U, 0xeded2cc1U,
    0x20206040U, 0xfcfc1fe3U, 0xb1b1c879U, 0x5b5bedb6U,
    0x6a6abed4U, 0xcbcb468dU, 0xbebed967U, 0x39394b72U,
    0x4a4ade94U, 0x4c4cd498U, 0x5858e8b0U, 0xcfcf4a85U,
    0xd0d06bbbU, 0xefef2ac5U, 0xaaaae54fU, 0xfbfb16edU,
    0x4343c586U, 0x4d4dd79aU, 0x33335566U, 0x85859411U,
    0x4545cf8aU, 0xf9f910e9U, 0x02020604U, 0x7f7f81feU,
    0x5050f0a0U, 0x3c3c4478U, 0x9f9fba25U, 0xa8a8e34bU,
    0x5151f3a2U, 0xa3a3fe5dU, 0x4040c080U, 0x8f8f8a05U,
    0x9292ad3fU, 0x9d9dbc21U, 0x38384870U, 0xf5f504f1U,
    0xbcbcdf63U, 0xb6b6c177U, 0xdada75afU, 0x21216342U,
    0x10103020U, 0xffff1ae5U, 0xf3f30efdU, 0xd2d26dbfU,
    0xcdcd4c81U, 0x0c0c1418U, 0x13133526U, 0xecec2fc3U,
    0x5f5fe1beU, 0x9797a235U, 0x4444cc88U, 0x1717392eU,
    0xc4c45793U, 0xa7a7f255U, 0x7e7e82fcU, 0x3d3d477aU,
    0x6464acc8U, 0x5d5de7baU, 0x19192b32U, 0x737395e6U,
    0x6060a0c0U, 0x81819819U, 0x4f4fd19eU, 0xdcdc7fa3U,
    0x22226644U, 0x2a2a7e54U, 0x9090ab3bU, 0x8888830bU,
    0x4646ca8cU, 0xeeee29c7U, 0xb8b8d36bU, 0x14143c28U,
    0xdede79a7U, 0x5e5ee2bcU, 0x0b0b1d16U, 0xdbdb76adU,
    0xe0e03bdbU, 0x32325664U, 0x3a3a4e74U, 0x0a0a1e14U,
    0x4949db92U, 0x06060a0cU, 0x24246c48U, 0x5c5ce4b8U,
    0xc2c25d9fU, 0xd3d36ebdU, 0xacacef43U, 0x6262a6c4U,
    0x9191a839U, 0x9595a431U, 0xe4e437d3U, 0x79798bf2U,
    0xe7e732d5U, 0xc8c8438bU, 0x3737596eU, 0x6d6db7daU,
    0x8d8d8c01U, 0xd5d564b1U, 0x4e4ed29cU, 0xa9a9e049U,
    0x6c6cb4d8U, 0x5656faacU, 0xf4f407f3U, 0xeaea25cfU,
    0x6565afcaU, 0x7a7a8ef4U, 0xaeaee947U, 0x08081810U,
    0xbabad56fU, 0x787888f0U, 0x25256f4aU, 0x2e2e725cU,
    0x1c1c2438U, 0xa6a6f157U, 0xb4b4c773U, 0xc6c65197U,
    0xe8e823cbU, 0xdddd7ca1U, 0x74749ce8U, 0x1f1f213eU,
    0x4b4bdd96U, 0xbdbddc61U, 0x8b8b860dU, 0x8a8a850fU,
    0x707090e0U, 0x3e3e427cU, 0xb5b5c471U, 0x6666aaccU,
    0x4848d890U, 0x03030506U, 0xf6f601f7U, 0x0e0e121cU,
    0x6161a3c2U, 0x35355f6aU, 0x5757f9aeU, 0xb9b9d069U,
    0x86869117U, 0xc1c15899U, 0x1d1d273aU, 0x9e9eb927U,
    0xe1e138d9U, 0xf8f813ebU, 0x9898b32bU, 0x11113322U,
    0x6969bbd2U, 0xd9d970a9U, 0x8e8e8907U, 0x9494a733U,
    0x9b9bb62dU, 0x1e1e223cU, 0x87879215U, 0xe9e920c9U,
    0xcece4987U, 0x5555ffaaU, 0x28287850U, 0xdfdf7aa5U,
    0x8c8c8f03U, 0xa1a1f859U, 0x89898009U, 0x0d0d171aU,
    0xbfbfda65U, 0xe6e631d7U, 0x4242c684U, 0x6868b8d0U,
    0x4141c382U, 0x9999b029U, 0x2d2d775aU, 0x0f0f111eU,
    0xb0b0cb7bU, 0x5454fca8U, 0xbbbbd66dU, 0x16163a2cU,
};

#define SPEC_ANN __attribute__((section(".non-speculative")))

#ifdef FULL_SG_PROTECT
#  define SPEC_ANN_OUTPUT __attribute__((section(".non-speculative")))
#else
#  define SPEC_ANN_OUTPUT
#endif

    /* u32 s0_ SPEC_ANN; */
    /* u32 s1_ SPEC_ANN; */
    /* u32 s2_ SPEC_ANN; */
    /* u32 s3_ SPEC_ANN; */

/* For manually inlined encryption code */
u32 s0 SPEC_ANN;
u32 s1 SPEC_ANN;
u32 s2 SPEC_ANN;
u32 s3 SPEC_ANN;

u32 t0 SPEC_ANN;
u32 t1 SPEC_ANN;
u32 t2 SPEC_ANN;
u32 t3 SPEC_ANN;

char cipher_buf[4096] SPEC_ANN_OUTPUT;
char checksum1 SPEC_ANN_OUTPUT;
char checksum2 SPEC_ANN_OUTPUT;

/*  The value of the secret key stored in the binary. We do not suggest
    storing secrets in binaries, this is just used to show how to mark 
    data as non-speculative through the Linux loader. I.E. This data
    will be non-speculative at load time.
*/
char aes_key_value[] __attribute__ ((section (".non-speculative"))) = "01234567890123456789012345678901";
// char aes_key_value[] __attribute__ ((nospec)) = "01234567890123456789012345678901";

#define COMPUTE_OUT(buf, i) (buf + (i * 16))

int main( int argc, char ** argv )
{
    register uint64_t time1, time2, time_work, time_encrypt;
    unsigned int junk;
    int i, j, k;
    unsigned int index;
    int work_loop, crypto_loop;
    
    AES_KEY * my_aes_key;
    

    
    // parse user input
    if( argc != 2 )
    {
        printf("usage test_### [75 50 25 10]\n");
        return 1;
    }
    
    if( !strcmp(argv[1], "75") )
    {
        work_loop = 2048;
        crypto_loop = 100;
    }
    else if( !strcmp(argv[1], "50") )
    {
        work_loop = 8192;
        crypto_loop = 100;
    }
    else if( !strcmp(argv[1], "25") )
    {
        work_loop = 8192;
        crypto_loop = 40;
    }
    else if( !strcmp(argv[1], "10") )
    {
        work_loop = 8192;
        crypto_loop = 15;
    }
    else
    {
        printf("usage test_### [75 50 25 10]\n");
        return 1;
    }
    
    // ensure all involved data is not going to page fault.
    for( i = 0; i < 1600; i++ )
    {
        plain_in.data[i] = plain_text_orig.data[i];
    }
    for( i = 0; i < 1024; i++ )
    {
        plain_in.data[i] = random_dat.data[i*4];
    }
    memset(plain_in_data, 0, 8192);
    memset(cipher_buf, 0, 4096);
    
    // allocate secret key
    my_aes_key = alloc_key();
    AES_set_encrypt_key((const unsigned char *)aes_key_value, 256, my_aes_key);
    
    time_work = 0;
    time_encrypt = 0;
    
    for( k = 0; k < 100; k++ )
    {
        checksum1 = 0;
        checksum2 = 0;
        time1 = __rdtscp( & junk);
        time1 = __rdtscp( & junk);
        for( j = 0; j < work_loop; j++ )
        {
            // do Work section
            // Speculative load based on speculative load is difficult
            // for Spectre defenses to mitigate without performance loss
            index = get_int( &random_dat, j % 1024 );
            set_byte( &plain_in, j, get_byte( &plain_text_orig, index ) );
        }
        time2 = __rdtscp( & junk) - time1;
        time2 = __rdtscp( & junk) - time1;
        time_work += time2;
    
        time1 = __rdtscp( & junk);
        time1 = __rdtscp( & junk);
        for( i = 0; i < crypto_loop; i++ )
        {
            // do Encrypt section //
            /* AES_encrypt((const unsigned char *)(plain_in_data + (i * 16)), (unsigned char *)(cipher_buf + (i * 16)), (const AES_KEY *)my_aes_key); */
            {
            const unsigned char *in = (const unsigned char *)(plain_in_data + (i * 16));
            /* unsigned char *out = (unsigned char *)(cipher_buf + (i * 16)); */

            const u32 *rk;
            u32 s0, s1, s2, s3, t0, t1, t2, t3;
#ifndef FULL_UNROLL
            int r;
#endif /* ?FULL_UNROLL */

            /* assert(in && out && my_aes_key); */
            rk = my_aes_key->rd_key;

            /*
             * map byte array block to cipher state
             * and add initial round key:
             */
            s0 = GETU32(in     ) ^ rk[0];
            s1 = GETU32(in +  4) ^ rk[1];
            s2 = GETU32(in +  8) ^ rk[2];
            s3 = GETU32(in + 12) ^ rk[3];
#ifdef FULL_UNROLL
            /* round 1: */
            t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[ 4];
            t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[ 5];
            t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[ 6];
            t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[ 7];
            /* round 2: */
            s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[ 8];
            s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[ 9];
            s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[10];
            s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[11];
            /* round 3: */
            t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[12];
            t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[13];
            t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[14];
            t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[15];
            /* round 4: */
            s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[16];
            s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[17];
            s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[18];
            s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[19];
            /* round 5: */
            t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[20];
            t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[21];
            t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[22];
            t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[23];
            /* round 6: */
            s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[24];
            s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[25];
            s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[26];
            s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[27];
            /* round 7: */
            t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[28];
            t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[29];
            t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[30];
            t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[31];
            /* round 8: */
            s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[32];
            s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[33];
            s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[34];
            s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[35];
            /* round 9: */
            t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[36];
            t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[37];
            t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[38];
            t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[39];
            if (my_aes_key->rounds > 10) {
                /* round 10: */
                s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[40];
                s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[41];
                s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[42];
                s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[43];
                /* round 11: */
                t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[44];
                t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[45];
                t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[46];
                t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[47];
                if (my_aes_key->rounds > 12) {
                    /* round 12: */
                    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[48];
                    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[49];
                    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[50];
                    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[51];
                    /* round 13: */
                    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[52];
                    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[53];
                    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[54];
                    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[55];
                }
            }
            rk += my_aes_key->rounds << 2;
#else  /* !FULL_UNROLL */
            /*
             * Nr - 1 full rounds:
             */
            r = my_aes_key->rounds >> 1;
            for (;;) {
                t0 =
                    Te0[(s0 >> 24)       ] ^
                    Te1[(s1 >> 16) & 0xff] ^
                    Te2[(s2 >>  8) & 0xff] ^
                    Te3[(s3      ) & 0xff] ^
                    rk[4];
                t1 =
                    Te0[(s1 >> 24)       ] ^
                    Te1[(s2 >> 16) & 0xff] ^
                    Te2[(s3 >>  8) & 0xff] ^
                    Te3[(s0      ) & 0xff] ^
                    rk[5];
                t2 =
                    Te0[(s2 >> 24)       ] ^
                    Te1[(s3 >> 16) & 0xff] ^
                    Te2[(s0 >>  8) & 0xff] ^
                    Te3[(s1      ) & 0xff] ^
                    rk[6];
                t3 =
                    Te0[(s3 >> 24)       ] ^
                    Te1[(s0 >> 16) & 0xff] ^
                    Te2[(s1 >>  8) & 0xff] ^
                    Te3[(s2      ) & 0xff] ^
                    rk[7];

                rk += 8;
                if (--r == 0) {
                    break;
                }

                s0 =
                    Te0[(t0 >> 24)       ] ^
                    Te1[(t1 >> 16) & 0xff] ^
                    Te2[(t2 >>  8) & 0xff] ^
                    Te3[(t3      ) & 0xff] ^
                    rk[0];
                s1 =
                    Te0[(t1 >> 24)       ] ^
                    Te1[(t2 >> 16) & 0xff] ^
                    Te2[(t3 >>  8) & 0xff] ^
                    Te3[(t0      ) & 0xff] ^
                    rk[1];
                s2 =
                    Te0[(t2 >> 24)       ] ^
                    Te1[(t3 >> 16) & 0xff] ^
                    Te2[(t0 >>  8) & 0xff] ^
                    Te3[(t1      ) & 0xff] ^
                    rk[2];
                s3 =
                    Te0[(t3 >> 24)       ] ^
                    Te1[(t0 >> 16) & 0xff] ^
                    Te2[(t1 >>  8) & 0xff] ^
                    Te3[(t2      ) & 0xff] ^
                    rk[3];
            }
#endif /* ?FULL_UNROLL */
            /*
             * apply last round and
             * map cipher state to byte array block:
             */
            s0 =
                (Te2[(t0 >> 24)       ] & 0xff000000) ^
                (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
                (Te0[(t2 >>  8) & 0xff] & 0x0000ff00) ^
                (Te1[(t3      ) & 0xff] & 0x000000ff) ^
                rk[0];
            PUTU32(COMPUTE_OUT(cipher_buf, i)     , s0);
            s1 =
                (Te2[(t1 >> 24)       ] & 0xff000000) ^
                (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
                (Te0[(t3 >>  8) & 0xff] & 0x0000ff00) ^
                (Te1[(t0      ) & 0xff] & 0x000000ff) ^
                rk[1];
            PUTU32(COMPUTE_OUT(cipher_buf, i) +  4, s1);
            s2 =
                (Te2[(t2 >> 24)       ] & 0xff000000) ^
                (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
                (Te0[(t0 >>  8) & 0xff] & 0x0000ff00) ^
                (Te1[(t1      ) & 0xff] & 0x000000ff) ^
                rk[2];
            PUTU32(COMPUTE_OUT(cipher_buf, i) +  8, s2);
            s3 =
                (Te2[(t3 >> 24)       ] & 0xff000000) ^
                (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
                (Te0[(t1 >>  8) & 0xff] & 0x0000ff00) ^
                (Te1[(t2      ) & 0xff] & 0x000000ff) ^
                rk[3];
            PUTU32(COMPUTE_OUT(cipher_buf, i) + 12, s3);
            }


            // Compute checksum
            for (int j = 0; j < 16; ++j)
            {
              /* if (((i*16) + j) % 2 == 0) */
              if (cipher_buf[j] % 2)
              {
                checksum1 ^= cipher_buf[(i*16) + j];
              }
              else
              {
                checksum2 ^= cipher_buf[(i*16) + j];
              }
            }
        }
        time2 = __rdtscp( & junk) - time1;
        time2 = __rdtscp( & junk) - time1;
        time_encrypt += time2;
    }
    
    // print the final execution times
    printf("work time   :[%lu]\n", time_work    );
    printf("encrypt time:[%lu]\n", time_encrypt );
    printf("total time  :[%lu]\n", time_work + time_encrypt);
    
    return 0;
}
