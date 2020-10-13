#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"
#include <unistd.h>
#include "stdatomic.h"
#include "icp_sal_user.h"
#include "cpa_dc.h"
#include "icp_sal_poll.h"

#include "qat_utils.h"
#include "qat_hash.h"

#ifdef USER_SPACE
#define MAX_INSTANCES 1024
#else
#define MAX_INSTANCES 1
#endif

#define DIGEST_LENGTH 16

#ifdef DO_CRYPTO
static sampleThread gPollingThread;
static int gPollingCy = 0;
#endif

#define MAX_ENGINES	18
#define BUFF_SIZE (128*1024*1024)
#define CONT_PIECE_SIZE (4*1024*1024)
#define CONT_PIECE_NUM (BUFF_SIZE/CONT_PIECE_SIZE)
typedef struct _engine_s {
	Cpa8U* pSrcBuffers[CONT_PIECE_NUM+1];
	CpaBufferList *pBufferList;
	Cpa8U *pBufferMeta;
	CpaCySymOpData *pOpData;
	struct COMPLETION_STRUCT complete;
	
	atomic_int used;
	Cpa32U instance_index;
	Cpa32U len;			//input len
} engine_s;

typedef struct _instance_s {
	CpaInstanceHandle cyInstHandle;
	CpaCySymSessionCtx sessionCtx;
} instance_s;

static instance_s* g_instances = NULL;
static int g_instance_num = 0;
static engine_s g_engines[MAX_ENGINES] = {0};

static int g_inited = 0;
int gDebugParam = 1;

#define TIMEOUT_MS 5000 /* 5 seconds*/

static void symCallback(void *pCallbackTag,
                        CpaStatus status,
                        const CpaCySymOp operationType,
                        void *pOpData,
                        CpaBufferList *pDstBuffer,
                        CpaBoolean verifyResult)
{
    //PRINT_DBG("Callback called with status = %d.\n", status);

    if (NULL != pCallbackTag)
    {
        /** indicate that the function has been called*/
        COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
    }
}

#ifdef DO_CRYPTO

CpaStatus init_instance(CpaInstanceHandle cyInstHandle) {
	/* Start Cryptographic component */
    //PRINT_DBG("cpaCyStartInstance\n");
    CpaStatus status = cpaCyStartInstance(cyInstHandle);
	
    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * Set the address translation function for the instance
         */
        status = cpaCySetAddressTranslation(cyInstHandle, sampleVirtToPhys);
    }
	
	if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * If the instance is polled start the polling thread. Note that
         * how the polling is done is implementation-dependent.
         */
        sampleCyStartPolling(cyInstHandle);
	}
	
	return status;
}

void init_session(CpaInstanceHandle cyInstHandle, CpaCySymSessionCtx *ret_sessionCtx)
{
	CpaStatus status = CPA_STATUS_SUCCESS;
	Cpa32U sessionCtxSize = 0;
	CpaCySymSessionSetupData sessionSetupData = {0};
	
    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * We now populate the fields of the session operational data and create
         * the session.  Note that the size required to store a session is
         * implementation-dependent, so we query the API first to determine how
         * much memory to allocate, and then allocate that memory.
         */

        /* populate symmetric session data structure
         * for a plain hash operation */
        sessionSetupData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
        sessionSetupData.symOperation = CPA_CY_SYM_OP_HASH;
        sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_MD5;
        sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_PLAIN;
        sessionSetupData.hashSetupData.digestResultLenInBytes = DIGEST_LENGTH;
        /* Place the digest result in a buffer unrelated to srcBuffer */
        sessionSetupData.digestIsAppended = CPA_FALSE;
        /* Generate the digest */
        sessionSetupData.verifyDigest = CPA_FALSE;

        /* Determine size of session context to allocate */
        //PRINT_DBG("cpaCySymSessionCtxGetSize\n");
        status = cpaCySymSessionCtxGetSize(
            cyInstHandle, &sessionSetupData, &sessionCtxSize);
			
		if (CPA_STATUS_SUCCESS == status)
	    {
	        /* Allocate session context */
	        status = PHYS_CONTIG_ALLOC(ret_sessionCtx, sessionCtxSize);
	    }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Initialize the Hash session */
        //PRINT_DBG("cpaCySymInitSession\n");
        status = cpaCySymInitSession(
            cyInstHandle, symCallback, &sessionSetupData, *ret_sessionCtx);
    }
}

CpaStatus CyInitInstances()
{
    CpaInstanceHandle cyInstHandles[MAX_INSTANCES];
    Cpa16U numInstances = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = cpaCyGetNumInstances(&numInstances);
    PRINT_DBG("instance total number %d\n", numInstances);
    if (numInstances >= MAX_INSTANCES)
    {
        numInstances = MAX_INSTANCES;
    }
    if ((status == CPA_STATUS_SUCCESS) && (numInstances > 0))
    {
        status = cpaCyGetInstances(numInstances, cyInstHandles);
        if (status == CPA_STATUS_SUCCESS) {
			g_instance_num = numInstances;
			g_instances = (instance_s*)malloc(sizeof(instance_s)*numInstances);
			memset(g_instances, 0, sizeof(instance_s)*numInstances);
			if(!g_instances) {
				return CPA_STATUS_FAIL;
			}
			for(int i=0; i<numInstances; i++) {
				g_instances[i].cyInstHandle = cyInstHandles[i];
				init_instance(cyInstHandles[i]);
				init_session(cyInstHandles[i], &g_instances[i].sessionCtx);
			}
		}
    }

	return status;
}

void symSessionWaitForInflightReq(CpaCySymSessionCtx pSessionCtx)
{

/* Session reuse is available since Cryptographic API version 2.2 */
#if CY_API_VERSION_AT_LEAST(2, 2)
    CpaBoolean sessionInUse = CPA_FALSE;

    do
    {
        cpaCySymSessionInUse(pSessionCtx, &sessionInUse);
    } while (sessionInUse);
#endif

    return;
}
#endif

#ifdef DO_CRYPTO
static void sal_polling(CpaInstanceHandle cyInstHandle)
{
    gPollingCy = 1;
    while (gPollingCy)
    {
        icp_sal_CyPollInstance(cyInstHandle, 0);
        OS_SLEEP(10);
    }

    sampleThreadExit();
}
#endif

/*
 * This function checks the instance info. If the instance is
 * required to be polled then it starts a polling thread.
 */
#ifdef DO_CRYPTO
void sampleCyStartPolling(CpaInstanceHandle cyInstHandle)
{
    CpaInstanceInfo2 info2 = {0};
    CpaStatus status = CPA_STATUS_SUCCESS;

    status = cpaCyInstanceGetInfo2(cyInstHandle, &info2);
    if ((status == CPA_STATUS_SUCCESS) && (info2.isPolled == CPA_TRUE))
    {
        /* Start thread to poll instance */
        sampleThreadCreate(&gPollingThread, sal_polling, cyInstHandle);
    }
}
#endif
/*
 * This function stops the polling of a crypto instance.
 */
#ifdef DO_CRYPTO
void sampleCyStopPolling(void)
{
    gPollingCy = 0;
    OS_SLEEP(10);
}
#endif

//--------------------------------------------------------------------------

static CpaStatus hashPerformOp(CpaInstanceHandle cyInstHandle, 
	CpaCySymSessionCtx sessionCtx, int eng_i, Cpa8U *digest)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBufferList *pBufferList = NULL;
    CpaCySymOpData *pOpData = NULL;
	engine_s *eng = &g_engines[eng_i];
	int n;
	CpaFlatBuffer *pFlatBuffers;

    /* init pBufferList */
    {
		pBufferList = eng->pBufferList;
		n = (eng->len+CONT_PIECE_SIZE-1) / CONT_PIECE_SIZE;

        pFlatBuffers = (CpaFlatBuffer *)(pBufferList + 1);

        pBufferList->pBuffers = pFlatBuffers;
        pBufferList->numBuffers = n+1;
        pBufferList->pPrivateMetaData = eng->pBufferMeta;

		for(int i=0; i<n; i++) {
	        pFlatBuffers[i].dataLenInBytes = CONT_PIECE_SIZE;
	        pFlatBuffers[i].pData = eng->pSrcBuffers[i];
		}
		
		if(eng->len % CONT_PIECE_SIZE) //last item not fully used up CONT_PIECE_SIZE
			pFlatBuffers[n-1].dataLenInBytes = eng->len % CONT_PIECE_SIZE;
			
		pFlatBuffers[n].dataLenInBytes = DIGEST_LENGTH;
	    pFlatBuffers[n].pData = eng->pSrcBuffers[n];
    }

    /* init pOpData */
    {
		pOpData = eng->pOpData;
        pOpData->sessionCtx = sessionCtx;
        pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        pOpData->hashStartSrcOffsetInBytes = 0;
        pOpData->messageLenToHashInBytes = eng->len;
        pOpData->pDigestResult = eng->pSrcBuffers[n];
    }

	//PRINT_DBG("len=%d, n=%d, first byte=%X, last byte=%X\n",
	//	eng->len, n, pFlatBuffers[0].pData[0], pFlatBuffers[n-1].pData[0]);

    /* calling QAT to do hash */
    {
        /** initialization for callback; the "complete" variable is used by the
         * callback function to indicate it has been called*/
        COMPLETION_INIT((&eng->complete));

        //PRINT_DBG("cpaCySymPerformOp\n");

        /** Perform symmetric operation */
        status = cpaCySymPerformOp(
            cyInstHandle,
            (void *)&eng->complete, /* data sent as is to the callback function*/
            pOpData,           /* operational data struct */
            pBufferList,       /* source buffer list */
            pBufferList,       /* same src & dst for an in-place operation*/
            NULL);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymPerformOp failed. (status = %d)\n", status);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            /** wait until the completion of the operation*/
            if (!COMPLETION_WAIT((&eng->complete), TIMEOUT_MS))
            {
                PRINT_ERR("timeout or interruption in cpaCySymPerformOp\n");
                status = CPA_STATUS_FAIL;
            }
        }

        if (CPA_STATUS_SUCCESS == status)
        {
			memcpy(digest, pOpData->pDigestResult, DIGEST_LENGTH);
        }
    }

    return status;
}

//-------------------------------------
int init_engines() {
	CpaStatus status = CPA_STATUS_SUCCESS;
	int i;
	Cpa32U bufferMetaSize = 0;
	Cpa32U numBuffers = CONT_PIECE_NUM+1;
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
		
	//PRINT_DBG("bufferMetaSize=%d.\n", bufferMetaSize);
	//PRINT_DBG("bufferListMemSize=%d.\n", bufferListMemSize);
		
	memset(g_engines, 0, sizeof(g_engines));
	
	for(i = 0; i<MAX_ENGINES; i++) {
		g_engines[i].instance_index = i%g_instance_num;
		
		CpaInstanceHandle cyInstHandle = g_instances[g_engines[i].instance_index].cyInstHandle;
		/* get meta information size */
	    status = cpaCyBufferListGetMetaSize(cyInstHandle, numBuffers, &bufferMetaSize);
		if (CPA_STATUS_SUCCESS != status)
			goto __Exit;
		//PRINT_DBG("instance:%d, bufferMetaSize=%d.\n", g_engines[i].instance_index, bufferMetaSize);
		
		status = PHYS_CONTIG_ALLOC(&g_engines[i].pBufferMeta, bufferMetaSize);
		if (CPA_STATUS_SUCCESS != status)
			goto __Exit;

	    status = OS_MALLOC(&g_engines[i].pBufferList, bufferListMemSize);
	    if (CPA_STATUS_SUCCESS != status)
			goto __Exit;

		for(int j = 0; j<CONT_PIECE_NUM; j++){
		    status = PHYS_CONTIG_ALLOC(&g_engines[i].pSrcBuffers[j], CONT_PIECE_SIZE);
		    if (CPA_STATUS_SUCCESS != status)
				goto __Exit;
		}
		status = PHYS_CONTIG_ALLOC(&g_engines[i].pSrcBuffers[CONT_PIECE_NUM], DIGEST_LENGTH);
	    if (CPA_STATUS_SUCCESS != status)
			goto __Exit;
		
		status = OS_MALLOC(&g_engines[i].pOpData, sizeof(CpaCySymOpData));
		if (CPA_STATUS_SUCCESS != status)
			goto __Exit;
	}
	
__Exit:
	if (CPA_STATUS_SUCCESS != status) {
		PRINT_DBG("Failed.\n");
		release_engines();
	}
		
	return status;
}

void reset_engine(int eng_i) {
	Cpa32U bufferMetaSize = 0;
	Cpa32U numBuffers = CONT_PIECE_NUM+1;
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
	
	if(!g_inited)
		return;
		
	/* zero memory */
	g_engines[eng_i].len = 0;
	memset(g_engines[eng_i].pBufferMeta, 0, bufferMetaSize);
	memset(g_engines[eng_i].pBufferList, 0, bufferListMemSize);
	/*
	for(int j = 0; j<CONT_PIECE_NUM; j++){
		memset(g_engines[eng_i].pSrcBuffers[j], 0, CONT_PIECE_SIZE);
	}*/
	memset(g_engines[eng_i].pSrcBuffers[CONT_PIECE_NUM], 0, DIGEST_LENGTH);
	memset(g_engines[eng_i].pOpData, 0, sizeof(CpaCySymOpData));
}

int get_engine() {
	if(!g_inited)
		return -1;
		
	for(int i = 0; i<MAX_ENGINES; i++) {
		if (g_engines[i].used)
			continue;
		
		if (atomic_fetch_add(&g_engines[i].used, 1) == 0) {
			reset_engine(i);
			return i;
		}
	}
	
	return -1;
}

void* get_engine_buffs(int eng_i) {
	return g_engines[eng_i].pSrcBuffers;
}

void release_engine(int eng_i) {
	if(!g_inited)
		return;
		
	atomic_store(&g_engines[eng_i].used, 0);
}

int release_engines() {
	for(int i = 0; i<MAX_ENGINES; i++) {
		/* At this stage, the callback function should have returned,
		 * so it is safe to free the memory */
		for(int j = 0; j<CONT_PIECE_NUM; j++) {
			if(g_engines[i].pSrcBuffers[j])
				PHYS_CONTIG_FREE(g_engines[i].pSrcBuffers[j]);
		}
		if(g_engines[i].pBufferList)
			OS_FREE(g_engines[i].pBufferList);
		if(g_engines[i].pBufferMeta)
			PHYS_CONTIG_FREE(g_engines[i].pBufferMeta);
		if(g_engines[i].pOpData)
			OS_FREE(g_engines[i].pOpData);

		COMPLETION_DESTROY(&g_engines[i].complete);
	}

	g_inited = 0;
	
	return 0;
}

int init_qat() {

    CpaStatus status = CPA_STATUS_SUCCESS;

    PRINT_DBG("init_qat() IN\n");
	
	if(g_inited)
		return 0;
	g_inited = 1;

    status = qaeMemInit();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to initialise memory driver\n");
        return (int)status;
    }

    status = icp_sal_userStartMultiProcess("SSL", CPA_FALSE);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to start user process SSL\n");
        qaeMemDestroy();
        return (int)status;
    }

	status = CyInitInstances();
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }
	
	status = init_engines();
	
    return status;
}

int md5_write(int eng_i, const unsigned char* buff, int len, int cp_mem) {
    int ori_len = len;
	int length;
	
	if(!g_inited)
		return -1;
		
    engine_s *eng = &g_engines[eng_i];
	if(eng->len + len > BUFF_SIZE)
		return -1; //input buffer too long
	
	int offset = eng->len % CONT_PIECE_SIZE;
	int i = eng->len / CONT_PIECE_SIZE;
	for(; len>0; i++) {
		offset = eng->len % CONT_PIECE_SIZE;
		i = eng->len / CONT_PIECE_SIZE;
		length = (CONT_PIECE_SIZE-offset)>len ? len : (CONT_PIECE_SIZE-offset);
		if(cp_mem)
			memcpy(&eng->pSrcBuffers[i][offset], &buff[ori_len-len], length);
		len -= length;
	}
	
	eng->len += ori_len;
	return 0;
}

void printx(unsigned char* buff, int len) {
	//int line_len = 8;
	printf("\n");
	for(int i = 0; i<len; i++) {
		//if(i%line_len == 0)
		//	printf("\n");
		printf("%X ", buff[i]);
	}
	printf("\n");
}

int md5_sum(int eng_i, Cpa8U *digest) {
    CpaStatus status = CPA_STATUS_SUCCESS;
	
	if(!g_inited)
		return -1;
		
	/* Perform Hash operation */
    status = hashPerformOp(
		g_instances[g_engines[eng_i].instance_index].cyInstHandle,
		g_instances[g_engines[eng_i].instance_index].sessionCtx,
		eng_i,
		digest);
	
	/*
	printx(digest, DIGEST_LENGTH);
	*/

    return (int)status;
}

int cleanup_qat() {
	CpaStatus status = CPA_STATUS_SUCCESS;
	int i = 0;
	
	if(!g_inited)
		return 0;
	
	for(i=0; i<g_instance_num; i++)
	{
		/* Wait for inflight requests before removing session */
	    symSessionWaitForInflightReq(g_instances[i].sessionCtx);
		
		/* Remove the session - session init has already succeeded */
	    PRINT_DBG("cpaCySymRemoveSession\n");
	    status = cpaCySymRemoveSession(g_instances[i].cyInstHandle, g_instances[i].sessionCtx);
		
		/* Free session Context */
	    PHYS_CONTIG_FREE(g_instances[i].sessionCtx);
		
		{//stat
			CpaCySymStats64 symStats = {0};
		    /* Query symmetric statistics */
		    status = cpaCySymQueryStats64(g_instances[i].cyInstHandle, &symStats);

		    if (CPA_STATUS_SUCCESS != status)
		    {
		        PRINT_ERR("cpaCySymQueryStats failed, status = %d\n", status);
		    }
		    else
		    {
		        PRINT_DBG("Number of symmetric operation completed: %llu\n",
		                  (unsigned long long)symStats.numSymOpCompleted);
		    }
		}
	}

    /* Stop the polling thread */
    sampleCyStopPolling();

	release_engines();

	for(i=0; i<g_instance_num; i++)
	{
	    PRINT_DBG("cpaCyStopInstance\n");
	    cpaCyStopInstance(g_instances[i].cyInstHandle);
	}
	
	//----------------------------
    icp_sal_userStop();
    qaeMemDestroy();
	
	g_inited = 0;
    return status;
}

int get_engine_num(){
	return MAX_ENGINES;
}

int get_max_object_size() {
	return BUFF_SIZE/(1024*1024);
}

int get_cont_piece_size() {
	return CONT_PIECE_SIZE;
}

int get_eng_current_len(int eng_i) {
	return g_engines[eng_i].len;
}

static int gHello = 2;
int helloworld(){
	PRINT_DBG("IN.\n");
	return gHello++;
}

