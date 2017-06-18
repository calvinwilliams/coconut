#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#define __USE_GNU
#include <sched.h>

#include "list.h"
#include "LOGC.h"
#include "fasterhttp.h"
#include "tcpdaemon.h"

/*
 * ����Ϊ ȫ����ˮ�ŷ�����
 */

/* �����ṩ��ȡ���к�URI */
#define URI_FETCH		"/fetch"
/* �����ṩ�������к�URI */
#define URI_EXPLAIN__SEQUENCE	"/explain?sequence="

/* ��ʮ�Ľ�λ���ַ��� */
static char sg_64_scale_system_charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_" ;

/* for testing
rmlog ; coconut -M SEQUENCE -p 9527 -c 1 --loglevel-debug --reserve 2 --server-no 1

curl http://127.0.0.1:9527/fetch
curl http://127.0.0.1:9527/explain?sequence=aR2001pe_LT00004

ps -ef | grep coconut | awk '{if($3==1)print $2}' | xargs kill
*/

/* for brench
rmlog ; ab -c 100 -n 100000 http://127.0.0.1:9527/fetch
*/

/*
 * ����Ϊ ȫ�ֶ�ȹ�����
 */

/* ��ѯ��� */
#define URI_QUERY		"/query"
/* ������ */
#define URI_APPLY__AMT		"/apply?amt="
/* ������ˮ */
#define URI_CANCEL__JNLSNO	"/cancel?jnlsno="
/* ������ */
#define URI_INCREASE__AMT	"/increase?amt="
/* �ۼ���� */
#define URI_DECREASE__AMT	"/decrease?amt="
/* ��ն�� */
#define URI_EMPTY		"/empty"

/* for testing
rmlog ; coconut -M LIMITAMT -p 9527 -c 1 --loglevel-debug --limit-amt 1000000 --export-jnls-amt-pathfilename $HOME/coconut_LIMITAMT.txt

curl http://127.0.0.1:9527/query
curl http://127.0.0.1:9527/apply?amt=1
curl http://127.0.0.1:9527/query
curl http://127.0.0.1:9527/apply?amt=2
curl http://127.0.0.1:9527/apply?amt=3
curl http://127.0.0.1:9527/apply?amt=4
curl http://127.0.0.1:9527/query
curl http://127.0.0.1:9527/cancel?jnlsno=3
curl http://127.0.0.1:9527/query
curl http://127.0.0.1:9527/increase?amt=5
curl http://127.0.0.1:9527/query
curl http://127.0.0.1:9527/decrease?amt=10
curl http://127.0.0.1:9527/query
curl http://127.0.0.1:9527/empty
curl http://127.0.0.1:9527/query
curl http://127.0.0.1:9527/increase?amt=50
curl http://127.0.0.1:9527/query
curl http://127.0.0.1:9527/apply?amt=50
curl http://127.0.0.1:9527/query

ps -ef | grep coconut | awk '{if($3==1)print $2}' | xargs kill
*/

/* for brench
rmlog ; coconut -M LIMITAMT -p 9527 -c 1 --loglevel-warn --limit-amt 10000000 --export-jnls-amt-pathfilename $HOME/coconut_JNLSNO_AMT.txt
*/

/*
 * ����Ϊ ��������
 */

/* ͨѶ������Ϣ�ṹ */
struct NetAddress
{
	char			ip[ 20 + 1 ] ;
	int			port ;
	SOCKET			sock ;
	struct sockaddr_in	addr ;
} ;

/* �ͻ������ӻỰ�ṹ */
struct AcceptedSession
{
	struct NetAddress	netaddr ;
	struct HttpEnv		*http ;
	struct list_head	unused_node ;
} ;

#define SESSIONCOUNT_OF_ARRAY	1024

struct AcceptedSessionArray
{
	struct AcceptedSession	accepted_session_array[ SESSIONCOUNT_OF_ARRAY ] ;
	
	struct list_head	prealloc_node ;
} ;

/* �����ڴ���Ϣ�ṹ */
struct ShareMemory
{
	int			proj_id ; /* ���ڼ��㹲���ڴ�key��ftok���� */
	key_t			shmkey ; /* �����ڴ�key */
	int			shmid ; /* �����ڴ�sequence_buffer */
	void			*base ; /* �����ڴ����ӻ���ַ */
	int			size ; /* �����ڴ��С */
} ;

/* ��ȷ�����ˮ��ϸ�� */

#define APPMODE_GLOBAL_SEQUENCE_SERVICE	1
#define APPMODE_GLOBAL_LIMITAMT_SERVICE	2

#define JNLSDETAILSCOUNT_IN_BLOCK	1000

/* ����˻����ṹ */
struct CoconutServerEnvironment
{
	char			listen_ip[ 20 + 1 ] ; /* ����IP */
	int			listen_port ; /* �����˿� */
	int			processor_count ; /* �������� */
	int			log_level ; /* ��־�ȼ� */
	char			*p_reserve ; /* ����ֵ */
	char			*p_server_no ; /* ��������� */
	char			*p_limit_amt ; /* �������ֵ */
	char			*p_export_jnls_amt_pathfilename ; /* ��������������ˮ��ϸ�ļ��� */
	int			cpu_affinity ;
	
	struct ShareMemory	data_space_shm ; /* �����ڴ�ϵͳ���� */
	int			app_mode ; /* Ӧ��ģʽ */
	
	struct AcceptedSessionArray	accepted_session_array_list ;
	struct AcceptedSession		accepted_session_unused_list ;
	
	union
	{
		struct GlobalSequenceService
		{
			/* ����Ϊ ȫ����ˮ�ŷ����� */
			uint64_t			reserve ; /* ����ֵ */
			uint64_t			server_no ; /* ��������� */
			char				sequence_buffer[ 16 + 1 ] ; /* ���к���������� */
			char				output_buffer[ 128 + 1 ] ; /* ��������� */
			int				output_buffer_len ; /* �����������Ч���� */
			struct SerialShareMemory
			{
				uint64_t		serial_no ; /* ��� */
			} *p_serial_shm ; /* �����ڴ�ָ�� */
		} global_sequence_service ;
		
		struct GlobalLimitAmtService
		{
			/* ����Ϊ ȫ�ֶ�ȹ����� */
			int64_t				limit_amt ; /* �������ֵ */
			char				*export_jnls_amt_pathfilename ; /* ��������������ˮ��ϸ�ļ��� */
			char				in_apply_flag ; /* �������ȱ�־ */
			char				output_buffer[ 128 + 1 ] ; /* ��������� */
			int				output_buffer_len ; /* �����������Ч���� */
			
			struct JnlsnoShareMemory
			{
				uint64_t		jnls_no ; /* ��ϸ��ˮ�� */
				int64_t			limit_amt ; /* ��ǰ��� */
			} *p_jnlsno_shm ; /* �����ڴ�ָ�� */
			
			struct JnlsDetailsBlock
			{
				struct JnlsDetails
				{
					uint64_t	jnls_no ; /* ��ϸ��ˮ�� */
					int64_t		amt ; /* ������ */
					unsigned char	valid ; /* ��Ч�� */
					uint64_t	cancel_jnls_no ; /* ��ϸ��ˮ�� */
				} jnls_details[ JNLSDETAILSCOUNT_IN_BLOCK ] ;
				int			jnls_details_count ; /* ������Ч��ϸ���� */
				
				struct list_head	prealloc_node ; /* ������ڵ� */
			} jnls_details_blocks , *p_current_jnls_details_blocks ; /* ��������ˮ��ϸ�� */
		} global_limitamt_service ;
	} app_data ;
} ;

/* ��NetAddress�����á��õ�IP��PORT�� */
#define SETNETADDRESS(_netaddr_) \
	memset( & ((_netaddr_).addr) , 0x00 , sizeof(struct sockaddr_in) ); \
	(_netaddr_).addr.sin_family = AF_INET ; \
	if( (_netaddr_).ip[0] == '\0' ) \
		(_netaddr_).addr.sin_addr.s_addr = INADDR_ANY ; \
	else \
		(_netaddr_).addr.sin_addr.s_addr = inet_addr((_netaddr_).ip) ; \
	(_netaddr_).addr.sin_port = htons( (unsigned short)((_netaddr_).port) );

#define GETNETADDRESS(_netaddr_) \
	strcpy( (_netaddr_).ip , inet_ntoa((_netaddr_).addr.sin_addr) ); \
	(_netaddr_).port = (int)ntohs( (_netaddr_).addr.sin_port ) ;

/* ��ʼ�����к�ǰ��� */
static int InitSequence( struct CoconutServerEnvironment *p_env )
{
	struct GlobalSequenceService	*p_global_sequence_service = & (p_env->app_data.global_sequence_service) ;
	uint64_t			index_region ;
	uint64_t			reserve_region_length = 1 ;
	uint64_t			server_no_region_length = 2 ;
	uint64_t			secondstamp_region_length = 6 ;
	uint64_t			serial_no_region_length = 5 ;
	
	/* ��ʼ����� */
	p_global_sequence_service->p_serial_shm->serial_no = 1 ;
	
	/*
	��һ�� ����Ŀ¼ 2����ʮ�Ľ����ַ� ��12��������λ
			��һ��3��������λ��ʾ��������ʮ�Ľ����ַ�����
			�ڶ���3��������λ��ʾ�������������ʮ�Ľ����ַ�����
			������3��������λ��ʾ�������ʮ�Ľ����ַ�����
			���Ķ�3��������λ��ʾ�������ʮ�Ľ����ַ�����
	�ڶ��� ������ 1����ʮ�Ľ����ַ� ��6��������λ����
	������ ����������� 2����ʮ�Ľ����ַ� �ɱ�ʾ4096̨������������
	������ ����� 6����ʮ�Ľ����ַ� �ɱ�ʾ2179������
	������ ����� 5����ʮ�Ľ����ַ� �������[1,10��]
			��16����ʮ�Ľ����ַ�
	*/
	
	/* ����Ŀ¼ */
	index_region = (reserve_region_length<<9) + (server_no_region_length<<6) + (secondstamp_region_length<<3) + (serial_no_region_length) ;
	p_global_sequence_service->sequence_buffer[0] = sg_64_scale_system_charset[(index_region>>6)&0x3F] ;
	p_global_sequence_service->sequence_buffer[1] = sg_64_scale_system_charset[index_region&0x3F] ;
	
	/* ������ */
	p_global_sequence_service->sequence_buffer[2] = sg_64_scale_system_charset[p_global_sequence_service->reserve&0x3F] ;
	
	/* ����������� */
	p_global_sequence_service->sequence_buffer[3] = sg_64_scale_system_charset[(p_global_sequence_service->server_no>>6)&0x3F] ;
	p_global_sequence_service->sequence_buffer[4] = sg_64_scale_system_charset[p_global_sequence_service->server_no&0x3F] ;
	
	return HTTP_OK;
}
		
/* ��ȡ���к� */
static int FetchSequence( struct CoconutServerEnvironment *p_env )
{
	struct GlobalSequenceService	*p_global_sequence_service = & (p_env->app_data.global_sequence_service) ;
	uint64_t			secondstamp ;
	uint64_t			ret_serial_no ;
	
	/* ����� */
	secondstamp = time( NULL );
	p_global_sequence_service->sequence_buffer[5] = sg_64_scale_system_charset[(secondstamp>>30)&0x3F] ;
	p_global_sequence_service->sequence_buffer[6] = sg_64_scale_system_charset[(secondstamp>>24)&0x3F] ;
	p_global_sequence_service->sequence_buffer[7] = sg_64_scale_system_charset[(secondstamp>>18)&0x3F] ;
	p_global_sequence_service->sequence_buffer[8] = sg_64_scale_system_charset[(secondstamp>>12)&0x3F] ;
	p_global_sequence_service->sequence_buffer[9] = sg_64_scale_system_charset[(secondstamp>>6)&0x3F] ;
	p_global_sequence_service->sequence_buffer[10] = sg_64_scale_system_charset[secondstamp&0x3F] ;
	
	/* ����� */
	ret_serial_no = __sync_fetch_and_add( & (p_global_sequence_service->p_serial_shm->serial_no) , 1 ) ; /* �������һ */
	p_global_sequence_service->sequence_buffer[11] = sg_64_scale_system_charset[(ret_serial_no>>24)&0x3F] ;
	p_global_sequence_service->sequence_buffer[12] = sg_64_scale_system_charset[(ret_serial_no>>18)&0x3F] ;
	p_global_sequence_service->sequence_buffer[13] = sg_64_scale_system_charset[(ret_serial_no>>12)&0x3F] ;
	p_global_sequence_service->sequence_buffer[14] = sg_64_scale_system_charset[(ret_serial_no>>6)&0x3F] ;
	p_global_sequence_service->sequence_buffer[15] = sg_64_scale_system_charset[ret_serial_no&0x3F] ;
	
	return HTTP_OK;
}

/* �������к� */
static int ExplainSequence( struct CoconutServerEnvironment *p_env , char *sequence )
{
	struct GlobalSequenceService	*p_global_sequence_service = & (p_env->app_data.global_sequence_service) ;
	char				*pos = NULL ;
	int				i ;
	uint64_t			index_region ;
	uint64_t			reserve_region_length ;
	uint64_t			server_no_region_length ;
	uint64_t			secondstamp_region_length ;
	uint64_t			serial_no_region_length ;
	
	uint64_t			reserve ;
	uint64_t			server_no ;
	time_t				secondstamp ;
	struct tm			stime ;
	uint64_t			serial_no ;
	
	index_region = 0 ;
	for( i = 0 ; i < 2 ; i++ )
	{
		if( (*sequence) == '\0' )
		{
			ERRORLOG(  "sequence too short" );
			return HTTP_BAD_REQUEST;
		}
		pos = strchr( sg_64_scale_system_charset , (*sequence) ) ;
		if( pos == NULL )
		{
			ERRORLOG(  "sequence invalid , char[%c]" , (*sequence) );
			return HTTP_BAD_REQUEST;
		}
		index_region = (index_region<<6) + (pos-sg_64_scale_system_charset) ;
		sequence++;
	}
	
	serial_no_region_length = (index_region&0x7) ; index_region >>= 3 ;
	secondstamp_region_length = (index_region&0x7) ; index_region >>= 3 ;
	server_no_region_length = (index_region&0x7) ; index_region >>= 3 ;
	reserve_region_length = (index_region&0x7) ; index_region >>= 3 ;
	
	reserve = 0 ;
	for( i = 0 ; i < reserve_region_length ; i++ )
	{
		if( (*sequence) == '\0' )
		{
			ERRORLOG(  "sequence too short" );
			return HTTP_BAD_REQUEST;
		}
		pos = strchr( sg_64_scale_system_charset , (*sequence) ) ;
		if( pos == NULL )
		{
			ERRORLOG(  "sequence invalid , char[%c]" , (*sequence) );
			return HTTP_BAD_REQUEST;
		}
		reserve = (reserve<<6) + (pos-sg_64_scale_system_charset) ;
		sequence++;
	}
	
	server_no = 0 ;
	for( i = 0 ; i < server_no_region_length ; i++ )
	{
		if( (*sequence) == '\0' )
		{
			ERRORLOG(  "sequence too short" );
			return HTTP_BAD_REQUEST;
		}
		pos = strchr( sg_64_scale_system_charset , (*sequence) ) ;
		if( pos == NULL )
		{
			ERRORLOG(  "sequence invalid , char[%c]" , (*sequence) );
			return HTTP_BAD_REQUEST;
		}
		server_no = (server_no<<6) + (pos-sg_64_scale_system_charset) ;
		sequence++;
	}
	
	secondstamp = 0 ;
	for( i = 0 ; i < secondstamp_region_length ; i++ )
	{
		if( (*sequence) == '\0' )
		{
			ERRORLOG(  "sequence too short" );
			return HTTP_BAD_REQUEST;
		}
		pos = strchr( sg_64_scale_system_charset , (*sequence) ) ;
		if( pos == NULL )
		{
			ERRORLOG(  "sequence invalid , char[%c]" , (*sequence) );
			return HTTP_BAD_REQUEST;
		}
		secondstamp = (secondstamp<<6) + (pos-sg_64_scale_system_charset) ;
		sequence++;
	}
	
	serial_no = 0 ;
	for( i = 0 ; i < serial_no_region_length ; i++ )
	{
		if( (*sequence) == '\0' )
		{
			ERRORLOG(  "sequence too short" );
			return HTTP_BAD_REQUEST;
		}
		pos = strchr( sg_64_scale_system_charset , (*sequence) ) ;
		if( pos == NULL )
		{
			ERRORLOG(  "sequence invalid , char[%c]" , (*sequence) );
			return HTTP_BAD_REQUEST;
		}
		serial_no = (serial_no<<6) + (pos-sg_64_scale_system_charset) ;
		sequence++;
	}
	
	memset( & stime , 0x00 , sizeof(struct tm) );
	localtime_r( & secondstamp , & stime );
	memset( p_global_sequence_service->output_buffer , 0x00 , sizeof(p_global_sequence_service->output_buffer) );
	p_global_sequence_service->output_buffer_len = snprintf( p_global_sequence_service->output_buffer , sizeof(p_global_sequence_service->output_buffer)-1
		, "reserve: %"PRIu64"  server_no: %"PRIu64"  secondstamp: %ld (%04d-%02d-%02d %02d:%02d:%02d)  serial_no: %"PRIu64"\n"
		, reserve , server_no , (long)secondstamp
		, stime.tm_year+1900 , stime.tm_mon+1 , stime.tm_mday , stime.tm_hour , stime.tm_min , stime.tm_sec
		, serial_no ) ;
	
	return HTTP_OK;
}

/* ���������ˮ��ϸ */
static int ExportJnlsAmtDetails( struct CoconutServerEnvironment *p_env )
{
	struct GlobalLimitAmtService	*p_global_limitamt_service = & (p_env->app_data.global_limitamt_service) ;
	pid_t				pid ;
	FILE				*fp = NULL ;
	struct JnlsDetailsBlock		*p_jnls_details_block = NULL ;
	int				i ;
	
	/* �����źž�� */
	signal( SIGCHLD , SIG_IGN );
	
	/* �����ӽ��� */
	pid = fork() ;
	if( pid == -1 )
		return -1;
	else if( pid > 0 )
		return 0;
	
	/* ������ˮ��ϸ */
	fp = fopen( p_global_limitamt_service->export_jnls_amt_pathfilename , "w" ) ;
	if( fp == NULL )
	{
		printf( "can't write file[%s]\n" , p_global_limitamt_service->export_jnls_amt_pathfilename );
		exit(0);
	}
	
	list_for_each_entry( p_jnls_details_block , & (p_global_limitamt_service->jnls_details_blocks.prealloc_node) , struct JnlsDetailsBlock , prealloc_node )
	{
		for( i = 0 ; i < p_jnls_details_block->jnls_details_count ; i++ )
		{
			if( p_jnls_details_block->jnls_details[i].valid == 1 )
				fprintf( fp , "%"PRIu64" %"PRId64"\n" , p_jnls_details_block->jnls_details[i].jnls_no , p_jnls_details_block->jnls_details[i].amt );
			else
				fprintf( fp , "%"PRIu64" %"PRId64" %"PRIu64"\n" , p_jnls_details_block->jnls_details[i].jnls_no , p_jnls_details_block->jnls_details[i].amt , p_jnls_details_block->jnls_details[i].cancel_jnls_no );
		}
	}
	
	fclose( fp );
	
	exit(0);
}

/* ��ʼ����� */
static int InitLimitAmt( struct CoconutServerEnvironment *p_env )
{
	struct GlobalLimitAmtService	*p_global_limitamt_service = & (p_env->app_data.global_limitamt_service) ;
	struct JnlsDetailsBlock		*p_jnls_details_block = NULL ;
	FILE				*fp = NULL ;
	
	p_global_limitamt_service->in_apply_flag = 1 ;
	
	p_global_limitamt_service->p_jnlsno_shm->jnls_no = 1 ;
	p_global_limitamt_service->p_jnlsno_shm->limit_amt = p_global_limitamt_service->limit_amt ;
	
	INIT_LIST_HEAD( & (p_global_limitamt_service->jnls_details_blocks.prealloc_node) );
	
	p_jnls_details_block = (struct JnlsDetailsBlock *)malloc( sizeof(struct JnlsDetailsBlock) ) ;
	if( p_jnls_details_block == NULL )
	{
		printf( "malloc failed , errno[%d]\n" , errno );
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	memset( p_jnls_details_block , 0x00 , sizeof(struct JnlsDetailsBlock) );
	list_add_tail( & (p_jnls_details_block->prealloc_node) , & (p_global_limitamt_service->jnls_details_blocks.prealloc_node) );
	
	p_global_limitamt_service->p_current_jnls_details_blocks = p_jnls_details_block ;
	
	/* ��������ļ� */
	fp = fopen( p_global_limitamt_service->export_jnls_amt_pathfilename , "w" ) ;
	if( fp == NULL )
	{
		printf( "can't write file[%s]\n" , p_global_limitamt_service->export_jnls_amt_pathfilename );
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	fclose( fp );
	
	return HTTP_OK;
}

/* ��ѯ��ǰ��� */
static int QueryCurrentLimitAmt( struct CoconutServerEnvironment *p_env )
{
	struct GlobalLimitAmtService	*p_global_limitamt_service = & (p_env->app_data.global_limitamt_service) ;
	
	p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "%"PRId64"\n" , p_global_limitamt_service->p_jnlsno_shm->limit_amt ) ;
	return HTTP_OK;
}

/* ������ */
static int ApplyLimitAmt( struct CoconutServerEnvironment *p_env , int64_t amt )
{
	struct GlobalLimitAmtService	*p_global_limitamt_service = & (p_env->app_data.global_limitamt_service) ;
	int64_t				old_limit_amt ;
	int64_t				new_limit_amt ;
	int64_t				ret_limit_amt ;
	struct JnlsDetailsBlock		*p_jnls_details_block = NULL ;
	
	if( amt < 0 )
	{
		p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "-1\n" ) ;
		return HTTP_OK;
	}
	
_GOTO_APPLY :
	
	if( p_global_limitamt_service->in_apply_flag == 1 )
	{
		while(1)
		{
			old_limit_amt = p_global_limitamt_service->p_jnlsno_shm->limit_amt ;
			if( old_limit_amt < 0 )
			{
				p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "0 0\n" ) ;
				p_global_limitamt_service->in_apply_flag = 0 ;
				ExportJnlsAmtDetails( p_env );
				return HTTP_OK;
			}
			
			new_limit_amt = old_limit_amt - amt ;
			if( new_limit_amt < 0 )
			{
				p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "0 %"PRId64"\n" , old_limit_amt ) ;
				p_global_limitamt_service->in_apply_flag = 0 ;
				ExportJnlsAmtDetails( p_env );
				return HTTP_OK;
			}
			
			ret_limit_amt = __sync_val_compare_and_swap( & (p_global_limitamt_service->p_jnlsno_shm->limit_amt) , old_limit_amt , new_limit_amt ) ;
			if( ret_limit_amt == old_limit_amt )
				break;
		}
		
		if( p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details_count+1 >= JNLSDETAILSCOUNT_IN_BLOCK )
		{
			p_jnls_details_block = (struct JnlsDetailsBlock *)malloc( sizeof(struct JnlsDetailsBlock) ) ;
			if( p_jnls_details_block == NULL )
			{
				printf( "malloc failed , errno[%d]\n" , errno );
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			memset( p_jnls_details_block , 0x00 , sizeof(struct JnlsDetailsBlock) );
			list_add_tail( & (p_jnls_details_block->prealloc_node) , & (p_global_limitamt_service->jnls_details_blocks.prealloc_node) );
			
			p_global_limitamt_service->p_current_jnls_details_blocks = p_jnls_details_block ;
		}
		
		p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details_count].jnls_no = __sync_fetch_and_add( & (p_global_limitamt_service->p_jnlsno_shm->jnls_no) , 1 ) ;
		p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details_count].amt = amt ;
		p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details_count].valid = 1 ;
		
		p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "%"PRIu64" %"PRId64"\n" , p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details_count].jnls_no , new_limit_amt ) ;
		p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details_count++;
		
		if( new_limit_amt == 0 )
		{
			p_global_limitamt_service->in_apply_flag = 0 ;
			ExportJnlsAmtDetails( p_env );
		}
	}
	else
	{
		if( p_global_limitamt_service->p_jnlsno_shm->limit_amt > 0 )
		{
			p_global_limitamt_service->in_apply_flag = 1 ;
			goto _GOTO_APPLY;
		}
		else
		{
			p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "0\n" ) ;
		}
	}
	
	return HTTP_OK;
}

/* ������� */
static int CancelApply( struct CoconutServerEnvironment *p_env , uint64_t jnls_no )
{
	struct GlobalLimitAmtService	*p_global_limitamt_service = & (p_env->app_data.global_limitamt_service) ;
	struct JnlsDetailsBlock		*p_jnls_details_block = NULL ;
	int				bottom , middle , top ;
	int64_t				old_limit_amt ;
	int64_t				new_limit_amt ;
	int64_t				ret_limit_amt ;
	
	if( jnls_no <= 0 )
	{
		p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "-1\n" ) ;
		return HTTP_OK;
	}
	
	list_for_each_entry( p_jnls_details_block , & (p_global_limitamt_service->jnls_details_blocks.prealloc_node) , struct JnlsDetailsBlock , prealloc_node )
	{
		if( p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details_count > 0
			&& jnls_no <= p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details_count-1].jnls_no )
		{
			bottom = 0 ;
			top = p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details_count-1 ;
			
			if( jnls_no == p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[bottom].jnls_no )
			{
				p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[bottom].valid = 0 ;
				p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "%"PRIu64"\n" , jnls_no ) ;
				return HTTP_OK;
			}
			
			if( top != bottom && jnls_no == p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[top].jnls_no )
			{
				p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[top].valid = 0 ;
				p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "%"PRIu64"\n" , jnls_no ) ;
				return HTTP_OK;
			}
			
			while(1)
			{
				/*
				2 = ( 1 + 3 ) / 2 ;
				1 = ( 1 + 2 ) / 2 ;
				2 = ( 1 + 4 ) / 2 ;
				*/
				middle = ( bottom + top ) / 2 ;
				if( middle == bottom )
					break;
				
				if( jnls_no == p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[middle].jnls_no )
				{
					if( p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[middle].valid == 0 )
					{
						p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "0\n" ) ;
						return HTTP_OK;
					}
					
					while(1)
					{
						old_limit_amt = p_global_limitamt_service->p_jnlsno_shm->limit_amt ;
						new_limit_amt = old_limit_amt + p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[middle].amt ;
						ret_limit_amt = __sync_val_compare_and_swap( & (p_global_limitamt_service->p_jnlsno_shm->limit_amt) , old_limit_amt , new_limit_amt ) ;
						if( ret_limit_amt == old_limit_amt )
							break;
					}
					
					p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[middle].valid = 0 ;
					p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[middle].cancel_jnls_no = __sync_fetch_and_add( & (p_global_limitamt_service->p_jnlsno_shm->jnls_no) , 1 ) ;
					p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "%"PRIu64" %"PRId64"\n" , p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[middle].cancel_jnls_no , new_limit_amt ) ;
					p_global_limitamt_service->in_apply_flag = 1 ;
					return HTTP_OK;
				}
				else if( jnls_no < p_global_limitamt_service->p_current_jnls_details_blocks->jnls_details[middle].jnls_no )
				{
					top = middle ;
				}
				else
				{
					bottom = middle ;
				}
			}
			
			break;
		}
	}
	
	p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "0\n" ) ;
	return HTTP_OK;
}

/* ���䵱ǰ��� */
static int IncreaseCurrentLimitAmt( struct CoconutServerEnvironment *p_env , int64_t amt )
{
	struct GlobalLimitAmtService	*p_global_limitamt_service = & (p_env->app_data.global_limitamt_service) ;
	int64_t				old_limit_amt ;
	int64_t				new_limit_amt ;
	int64_t				ret_limit_amt ;
	
	if( amt < 0 )
	{
		p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "-1\n" ) ;
		return HTTP_OK;
	}
	
	while(1)
	{
		old_limit_amt = p_global_limitamt_service->p_jnlsno_shm->limit_amt ;
		new_limit_amt = old_limit_amt + amt ;
		ret_limit_amt = __sync_val_compare_and_swap( & (p_global_limitamt_service->p_jnlsno_shm->limit_amt) , old_limit_amt , new_limit_amt ) ;
		if( ret_limit_amt == old_limit_amt )
			break;
	}
	
	p_global_limitamt_service->in_apply_flag = 1 ;
	
	p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "%"PRId64"\n" , new_limit_amt ) ;
	return HTTP_OK;
}

/* �ۼ���ǰ��� */
static int DecreaseCurrentLimitAmt( struct CoconutServerEnvironment *p_env , int64_t amt )
{
	struct GlobalLimitAmtService	*p_global_limitamt_service = & (p_env->app_data.global_limitamt_service) ;
	int64_t				old_limit_amt ;
	int64_t				new_limit_amt ;
	int64_t				ret_limit_amt ;
	
	if( amt < 0 )
	{
		p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "-1\n" ) ;
		return HTTP_OK;
	}
	
	while(1)
	{
		old_limit_amt = p_global_limitamt_service->p_jnlsno_shm->limit_amt ;
		new_limit_amt = old_limit_amt - amt ;
		if( new_limit_amt < 0 )
			new_limit_amt = 0 ;
		ret_limit_amt = __sync_val_compare_and_swap( & (p_global_limitamt_service->p_jnlsno_shm->limit_amt) , old_limit_amt , new_limit_amt ) ;
		if( ret_limit_amt == old_limit_amt )
			break;
	}
	
	if( new_limit_amt > 0 )
	{
		p_global_limitamt_service->in_apply_flag = 1 ;
	}
	else
	{
		p_global_limitamt_service->in_apply_flag = 0 ;
		ExportJnlsAmtDetails( p_env );
	}
	
	p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "%"PRId64"\n" , new_limit_amt ) ;
	return HTTP_OK;
}

/* ��յ�ǰ��� */
static int EmptyCurrentLimitAmt( struct CoconutServerEnvironment *p_env )
{
	struct GlobalLimitAmtService	*p_global_limitamt_service = & (p_env->app_data.global_limitamt_service) ;
	int64_t				old_limit_amt ;
	int64_t				new_limit_amt ;
	int64_t				ret_limit_amt ;
	
	while(1)
	{
		old_limit_amt = p_global_limitamt_service->p_jnlsno_shm->limit_amt ;
		new_limit_amt = 0 ;
		ret_limit_amt = __sync_val_compare_and_swap( & (p_global_limitamt_service->p_jnlsno_shm->limit_amt) , old_limit_amt , new_limit_amt ) ;
		if( ret_limit_amt == old_limit_amt )
			break;
	}
	
	p_global_limitamt_service->in_apply_flag = 0 ;
	ExportJnlsAmtDetails( p_env );
	
	p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "%"PRId64"\n" , new_limit_amt ) ;
	return HTTP_OK;
}

/* Ӧ�ò㴦�� */
static int DispatchProcess( struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	char			*uri = NULL ;
	int			uri_len ;
	
	int			nret = 0 ;
	
	/* �õ�URI */
	uri = GetHttpHeaderPtr_URI( p_accepted_session->http , & uri_len ) ;
	INFOLOG(  "uri[%.*s]" , uri_len , uri );
	
	if( p_env->app_mode == APPMODE_GLOBAL_SEQUENCE_SERVICE )
	{
		struct GlobalSequenceService	*p_global_sequence_service = & (p_env->app_data.global_sequence_service) ;
		
		/* ��ȡ���к� */
		if( uri_len == sizeof(URI_FETCH)-1 && MEMCMP( uri , == , URI_FETCH , uri_len ) )
		{
			nret = FetchSequence( p_env ) ;
			if( nret != HTTP_OK )
				return nret;
			
			nret = FormatHttpResponseStartLine( HTTP_OK , p_accepted_session->http , 0
				, "Content-length: %d" HTTP_RETURN_NEWLINE
				HTTP_RETURN_NEWLINE
				"%s\n" HTTP_RETURN_NEWLINE
				, sizeof(p_global_sequence_service->sequence_buffer)
				, p_global_sequence_service->sequence_buffer ) ;
			if( nret )
			{
				ERRORLOG(  "FormatHttpResponseStartLine failed[%d]" , nret );
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
		/* �������к� */
		else if( MEMCMP( uri , == , URI_EXPLAIN__SEQUENCE , sizeof(URI_EXPLAIN__SEQUENCE)-1 ) )
		{
			nret = ExplainSequence( p_env , uri+sizeof(URI_EXPLAIN__SEQUENCE)-1 ) ;
			if( nret != HTTP_OK )
				return nret;
			
			nret = FormatHttpResponseStartLine( HTTP_OK , p_accepted_session->http , 0
				, "Content-length: %d" HTTP_RETURN_NEWLINE
				HTTP_RETURN_NEWLINE
				"%.*s" HTTP_RETURN_NEWLINE
				, p_global_sequence_service->output_buffer_len
				, p_global_sequence_service->output_buffer_len , p_global_sequence_service->output_buffer ) ;
			if( nret )
			{
				ERRORLOG(  "FormatHttpResponseStartLine failed[%d]" , nret );
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
		else
		{
			return HTTP_NOT_FOUND;
		}
	}
	else if( p_env->app_mode == APPMODE_GLOBAL_LIMITAMT_SERVICE )
	{
		struct GlobalLimitAmtService	*p_global_limitamt_service = & (p_env->app_data.global_limitamt_service) ;
		
		/* ��ѯ��ǰ��� */
		if( uri_len == sizeof(URI_QUERY)-1 && MEMCMP( uri , == , URI_QUERY , uri_len ) )
		{
			nret = QueryCurrentLimitAmt( p_env ) ;
			if( nret != HTTP_OK )
				return nret;
			
			nret = FormatHttpResponseStartLine( HTTP_OK , p_accepted_session->http , 0
				, "Content-length: %d" HTTP_RETURN_NEWLINE
				HTTP_RETURN_NEWLINE
				"%.*s" HTTP_RETURN_NEWLINE
				, p_global_limitamt_service->output_buffer_len
				, p_global_limitamt_service->output_buffer_len , p_global_limitamt_service->output_buffer ) ;
			if( nret )
			{
				ERRORLOG(  "FormatHttpResponseStartLine failed[%d]" , nret );
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
		/* ������ */
		else if( MEMCMP( uri , == , URI_APPLY__AMT , sizeof(URI_APPLY__AMT)-1 ) )
		{
			nret = ApplyLimitAmt( p_env , (int64_t)atoll(uri+sizeof(URI_APPLY__AMT)-1) ) ;
			if( nret != HTTP_OK )
				return nret;
			
			nret = FormatHttpResponseStartLine( HTTP_OK , p_accepted_session->http , 0
				, "Content-length: %d" HTTP_RETURN_NEWLINE
				HTTP_RETURN_NEWLINE
				"%.*s\n" HTTP_RETURN_NEWLINE
				, p_global_limitamt_service->output_buffer_len
				, p_global_limitamt_service->output_buffer_len , p_global_limitamt_service->output_buffer ) ;
			if( nret )
			{
				ERRORLOG(  "FormatHttpResponseStartLine failed[%d]" , nret );
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
		/* ������� */
		else if( MEMCMP( uri , == , URI_CANCEL__JNLSNO , sizeof(URI_CANCEL__JNLSNO)-1 ) )
		{
			nret = CancelApply( p_env , (uint64_t)atoll(uri+sizeof(URI_CANCEL__JNLSNO)-1) ) ;
			if( nret != HTTP_OK )
				return nret;
			
			nret = FormatHttpResponseStartLine( HTTP_OK , p_accepted_session->http , 0
				, "Content-length: %d" HTTP_RETURN_NEWLINE
				HTTP_RETURN_NEWLINE
				"%.*s" HTTP_RETURN_NEWLINE
				, p_global_limitamt_service->output_buffer_len
				, p_global_limitamt_service->output_buffer_len , p_global_limitamt_service->output_buffer ) ;
			if( nret )
			{
				ERRORLOG(  "FormatHttpResponseStartLine failed[%d]" , nret );
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
		/* ���䵱ǰ��� */
		else if( MEMCMP( uri , == , URI_INCREASE__AMT , sizeof(URI_INCREASE__AMT)-1 ) )
		{
			nret = IncreaseCurrentLimitAmt( p_env , (int64_t)atoll(uri+sizeof(URI_INCREASE__AMT)-1) ) ;
			if( nret != HTTP_OK )
				return nret;
			
			nret = FormatHttpResponseStartLine( HTTP_OK , p_accepted_session->http , 0
				, "Content-length: %d" HTTP_RETURN_NEWLINE
				HTTP_RETURN_NEWLINE
				"%.*s" HTTP_RETURN_NEWLINE
				, p_global_limitamt_service->output_buffer_len
				, p_global_limitamt_service->output_buffer_len , p_global_limitamt_service->output_buffer ) ;
			if( nret )
			{
				ERRORLOG(  "FormatHttpResponseStartLine failed[%d]" , nret );
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
		/* �ۼ���ǰ��� */
		else if( MEMCMP( uri , == , URI_DECREASE__AMT , sizeof(URI_DECREASE__AMT)-1 ) )
		{
			nret = DecreaseCurrentLimitAmt( p_env , (int64_t)atoll(uri+sizeof(URI_DECREASE__AMT)-1) ) ;
			if( nret != HTTP_OK )
				return nret;
			
			nret = FormatHttpResponseStartLine( HTTP_OK , p_accepted_session->http , 0
				, "Content-length: %d" HTTP_RETURN_NEWLINE
				HTTP_RETURN_NEWLINE
				"%.*s" HTTP_RETURN_NEWLINE
				, p_global_limitamt_service->output_buffer_len
				, p_global_limitamt_service->output_buffer_len , p_global_limitamt_service->output_buffer ) ;
			if( nret )
			{
				ERRORLOG(  "FormatHttpResponseStartLine failed[%d]" , nret );
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
		/* ��յ�ǰ��� */
		else if( uri_len == sizeof(URI_EMPTY)-1 && MEMCMP( uri , == , URI_EMPTY , uri_len ) )
		{
			nret = EmptyCurrentLimitAmt( p_env ) ;
			if( nret != HTTP_OK )
				return nret;
			
			nret = FormatHttpResponseStartLine( HTTP_OK , p_accepted_session->http , 0
				, "Content-length: %d" HTTP_RETURN_NEWLINE
				HTTP_RETURN_NEWLINE
				"%.*s\n" HTTP_RETURN_NEWLINE
				, p_global_limitamt_service->output_buffer_len
				, p_global_limitamt_service->output_buffer_len , p_global_limitamt_service->output_buffer ) ;
			if( nret )
			{
				ERRORLOG(  "FormatHttpResponseStartLine failed[%d]" , nret );
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
		else
		{
			return HTTP_NOT_FOUND;
		}
	}
	else
	{
		return HTTP_NOT_FOUND;
	}
	
	return HTTP_OK;
}

/* Ԥ������пͻ��˻Ự�ṹ */
static int IncreaseAcceptedSessions( struct CoconutServerEnvironment *p_env )
{
	struct AcceptedSessionArray	*p_accepted_session_array = NULL ;
	struct AcceptedSession		*p_accepted_session = NULL ;
	int				i ;
	
	/* �������ӿ���HTTPͨѶ�Ự */
	p_accepted_session_array = (struct AcceptedSessionArray *)malloc( sizeof(struct AcceptedSessionArray) ) ;
	if( p_accepted_session_array == NULL )
	{
		ErrorLog( __FILE__ , __LINE__ , "malloc failed , errno[%d]" , ERRNO );
		return -1;
	}
	memset( p_accepted_session_array , 0x00 , sizeof(struct AcceptedSessionArray) );
	list_add_tail( & (p_accepted_session_array->prealloc_node) , & (p_env->accepted_session_array_list.prealloc_node) );
	
	for( i = 0 , p_accepted_session = p_accepted_session_array->accepted_session_array ; i < sizeof(p_accepted_session_array->accepted_session_array)/sizeof(p_accepted_session_array->accepted_session_array[0]) ; i++ , p_accepted_session++ )
	{
		p_accepted_session->http = CreateHttpEnv() ;
		if( p_accepted_session->http == NULL )
		{
			ERRORLOG(  "CreateHttpEnv failed , errno[%d]" , ERRNO );
			return TCPMAIN_RETURN_ERROR;
		}
		SetHttpTimeout( p_accepted_session->http , -1 );
		ResetHttpEnv( p_accepted_session->http );
		
		list_add_tail( & (p_accepted_session->unused_node) , & (p_env->accepted_session_unused_list.unused_node) );
		DebugLog( __FILE__ , __LINE__ , "init accepted session[%p]" , p_accepted_session );
	}
	
	return 0;
}

/* ��Ԥ����Ŀ��пͻ��˻Ự�ṹ��ȡ��һ�� */
static struct AcceptedSession *FetchAcceptedSessionUnused( struct CoconutServerEnvironment *p_env )
{
	struct AcceptedSession	*p_accepted_session = NULL ;
	
	int			nret = 0 ;
	
	/* ������пͻ��˻Ự����Ϊ�� */
	if( list_empty( & (p_env->accepted_session_unused_list.unused_node) ) )
	{
		nret = IncreaseAcceptedSessions( p_env ) ;
		if( nret )
			return NULL;
	}
	
	/* �ӿ���HTTPͨѶ�Ự�������Ƴ�һ���Ự��������֮ */
	p_accepted_session = list_first_entry( & (p_env->accepted_session_unused_list.unused_node) , struct AcceptedSession , unused_node ) ;
	list_del( & (p_accepted_session->unused_node) );
	
	DebugLog( __FILE__ , __LINE__ , "fetch accepted session[%p]" , p_accepted_session );
	ResetHttpEnv( p_accepted_session->http );
	return p_accepted_session;
}

/* �ѵ�ǰ�ͻ��˻Ự�Żؿ���������ȥ */
static void SetAcceptedSessionUnused( struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	DebugLog( __FILE__ , __LINE__ , "putback accepted session[%p]" , p_accepted_session );
	
	/* �ѵ�ǰ����HTTPͨѶ�Ự�Ƶ�����HTTPͨѶ�Ự������ */
	list_add_tail( & (p_accepted_session->unused_node) , & (p_env->accepted_session_unused_list.unused_node) );
	
	return;
}

/* �������пͻ�������Ự�ṹ */
static void FreeAllAcceptedSessionArray( struct CoconutServerEnvironment *p_env )
{
	struct list_head		*p_curr = NULL , *p_next = NULL ;
	struct AcceptedSessionArray	*p_accepted_session_array = NULL ;
	
	list_for_each_safe( p_curr , p_next , & (p_env->accepted_session_array_list.prealloc_node) )
	{
		p_accepted_session_array = container_of( p_curr , struct AcceptedSessionArray , prealloc_node ) ;
		list_del( & (p_accepted_session_array->prealloc_node) );
		
		free( p_accepted_session_array );
	}
	
	return;
}

/* ��������������¼� */
static int OnAcceptingSocket( struct TcpdaemonServerEnvironment *p , struct CoconutServerEnvironment *p_env , int sock , struct sockaddr *p_addr )
{
	struct AcceptedSession	*p_accepted_session = NULL ;
	
	/* �����ڴ��Դ�������ӻỰ */
	p_accepted_session = FetchAcceptedSessionUnused( p_env ) ;
	if( p_accepted_session == NULL )
		return TCPMAIN_RETURN_ERROR;
	
	p_accepted_session->netaddr.sock = sock ;
	memcpy( & (p_accepted_session->netaddr.addr) , & p_addr , sizeof(struct sockaddr) );
	
	/* ���������ӻỰ���ݽṹ */
	TDSetIoMultiplexDataPtr( p , p_accepted_session );
	
	/* �ȴ����¼� */
	return TCPMAIN_RETURN_WAITINGFOR_RECEIVING;
}

/* �����ر��׽��� */
static int OnClosingSocket( struct TcpdaemonServerEnvironment *p , struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	/* �ͷ������ӻỰ */
	INFOLOG(  "close session[%d]" , p_accepted_session->netaddr.sock );
	
	SetAcceptedSessionUnused( p_env , p_accepted_session );
	
	/* �ȴ���һ�����¼� */
	return TCPMAIN_RETURN_WAITINGFOR_NEXT;
}

/* ���տͻ����׽������� */
static int OnReceivingSocket( struct TcpdaemonServerEnvironment *p , struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	int			nret = 0 ;
	
	/* ������������ */
	nret = ReceiveHttpRequestNonblock( p_accepted_session->netaddr.sock , NULL , p_accepted_session->http ) ;
	if( nret == FASTERHTTP_INFO_NEED_MORE_HTTP_BUFFER )
	{
		DEBUGLOG(  "ReceiveHttpRequestNonblock[%d] return FASTERHTTP_INFO_NEED_MORE_HTTP_BUFFER" , p_accepted_session->netaddr.sock );
		return TCPMAIN_RETURN_WAITINGFOR_NEXT;
	}
	else if( nret == FASTERHTTP_INFO_TCP_CLOSE )
	{
		INFOLOG(  "ReceiveHttpRequestNonblock[%d] return CLOSE[%d]" , p_accepted_session->netaddr.sock , nret );
		return TCPMAIN_RETURN_CLOSE;
	}
	else if( nret )
	{
		ERRORLOG(  "ReceiveHttpRequestNonblock[%d] return ERROR[%d]" , p_accepted_session->netaddr.sock , nret );
		return TCPMAIN_RETURN_ERROR;
	}
	else
	{
		/* ���������� */
		DEBUGLOG(  "ReceiveHttpRequestNonblock[%d] return DONE" , p_accepted_session->netaddr.sock );
		
		/* ����Ӧ�ò� */
		nret = DispatchProcess( p_env , p_accepted_session ) ;
		if( nret != HTTP_OK )
		{
			nret = FormatHttpResponseStartLine( nret , p_accepted_session->http , 1 , NULL ) ;
			if( nret )
			{
				ERRORLOG(  "FormatHttpResponseStartLine failed[%d]" , nret );
				return TCPMAIN_RETURN_ERROR;
			}
		}
		
		return TCPMAIN_RETURN_WAITINGFOR_SENDING;
	}
}

/* ���Ϳͻ����׽������� */
static int OnSendingSocket( struct TcpdaemonServerEnvironment *p , struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	int			nret = 0 ;
	
	/* ������Ӧ���� */
	nret = SendHttpResponseNonblock( p_accepted_session->netaddr.sock , NULL , p_accepted_session->http ) ;
	if( nret == FASTERHTTP_INFO_TCP_SEND_WOULDBLOCK )
	{
		DEBUGLOG(  "SendHttpResponseNonblock[%d] return FASTERHTTP_INFO_TCP_SEND_WOULDBLOCK" , p_accepted_session->netaddr.sock );
		return TCPMAIN_RETURN_WAITINGFOR_NEXT;
	}
	else if( nret )
	{
		ERRORLOG(  "SendHttpResponseNonblock[%d] return ERROR[%d]" , p_accepted_session->netaddr.sock , nret );
		return TCPMAIN_RETURN_ERROR;
	}
	else
	{
		DEBUGLOG(  "SendHttpResponseNonblock[%d] return DONE" , p_accepted_session->netaddr.sock );
		
		if( ! CheckHttpKeepAlive(p_accepted_session->http) )
			return TCPMAIN_RETURN_CLOSE;
		
		SetHttpTimeout( p_accepted_session->http , -1 );
		ResetHttpEnv( p_accepted_session->http ) ;
		
		return TCPMAIN_RETURN_WAITINGFOR_RECEIVING;
	}
}

static func_tcpmain tcpmain ;
int tcpmain( struct TcpdaemonServerEnvironment *p , int sock , void *p_addr )
{
	struct CoconutServerEnvironment	*p_env = TDGetTcpmainParameter(p) ;
	
	switch( TDGetIoMultiplexEvent(p) )
	{
		case IOMP_ON_ACCEPTING_SOCKET :
			return OnAcceptingSocket( p , p_env , sock , (struct sockaddr *)p_addr ) ;
		case IOMP_ON_CLOSING_SOCKET :
			return OnClosingSocket( p , p_env , (struct AcceptedSession *)p_addr ) ;
		case IOMP_ON_RECEIVING_SOCKET :
			return OnReceivingSocket( p , p_env , (struct AcceptedSession *)p_addr ) ;
		case IOMP_ON_SENDING_SOCKET :
			return OnSendingSocket( p , p_env , (struct AcceptedSession *)p_addr ) ;
		default :
			return TCPMAIN_RETURN_ERROR;
	}
}

static void usage()
{
	printf( "coconut v0.0.7.1\n" );
	printf( "Copyright by calvin 2017\n" );
	printf( "USAGE : coconut -M (SEQUENCE|LIMITAMT) [ -l (listen_ip) ] -p (listen_port) [ -c (processor_count) ] [ --loglevel-(debug|info|warn|error|fatal) ] [ --cpu-affinity (begin_mask) ]\n" );
	printf( "                global serial service :\n" );
	printf( "                    --reserve (reserve) --server-no (server_no)\n" );
	printf( "                global limit-amt service :\n" );
	printf( "                    --limit-amt (amt) --export-jnls-amt-pathfilename (pathfilename)\n" );
	return;
}

int main( int argc , char *argv[] )
{
	struct CoconutServerEnvironment	env , *p_env = & env ;
	struct GlobalSequenceService	*p_global_sequence_service = & (p_env->app_data.global_sequence_service) ;
	struct GlobalLimitAmtService	*p_global_limitamt_service = & (p_env->app_data.global_limitamt_service) ;
	int				i ;
	struct TcpdaemonEntryParameter	para ;
	
	int				nret = 0 ;
	
	if( argc > 1 )
	{
		memset( & env , 0x00 , sizeof(struct CoconutServerEnvironment) );
		p_env->log_level = LOGLEVEL_WARN ;
		
		/* ���������в��� */
		for( i = 1 ; i < argc ; i++ )
		{
			if( strcmp( argv[i] , "-M" ) == 0 && i + 1 < argc )
			{
				++i;
				if( STRCMP( argv[i] , == , "SEQUENCE" ) )
				{
					p_env->app_mode = APPMODE_GLOBAL_SEQUENCE_SERVICE ;
				}
				else if( STRCMP( argv[i] , == , "LIMITAMT" ) )
				{
					p_env->app_mode = APPMODE_GLOBAL_LIMITAMT_SERVICE ;
				}
				else
				{
					printf( "Invalid command parameter value '%s' for -M\n" , argv[i] );
					usage();
					exit(7);
				}
			}
			else if( strcmp( argv[i] , "-l" ) == 0 && i + 1 < argc )
			{
				strncpy( p_env->listen_ip , argv[++i] , sizeof(p_env->listen_ip)-1 );
			}
			else if( strcmp( argv[i] , "-p" ) == 0 && i + 1 < argc )
			{
				p_env->listen_port = atoi(argv[++i]) ;
			}
			else if( strcmp( argv[i] , "-c" ) == 0 && i + 1 < argc )
			{
				p_env->processor_count = atoi(argv[++i]) ;
			}
			else if( strcmp( argv[i] , "--loglevel-debug" ) == 0 )
			{
				p_env->log_level = LOGLEVEL_DEBUG ;
			}
			else if( strcmp( argv[i] , "--loglevel-info" ) == 0 )
			{
				p_env->log_level = LOGLEVEL_INFO ;
			}
			else if( strcmp( argv[i] , "--loglevel-warn" ) == 0 )
			{
				p_env->log_level = LOGLEVEL_WARN ;
			}
			else if( strcmp( argv[i] , "--loglevel-error" ) == 0 )
			{
				p_env->log_level = LOGLEVEL_ERROR ;
			}
			else if( strcmp( argv[i] , "--loglevel-fatal" ) == 0 )
			{
				p_env->log_level = LOGLEVEL_FATAL ;
			}
			else if( strcmp( argv[i] , "--cpu-affinity" ) == 0 && i + 1 < argc )
			{
				p_env->cpu_affinity = atoi(argv[++i]) ;
			}
			else if( strcmp( argv[i] , "--reserve" ) == 0 && i + 1 < argc )
			{
				p_env->p_reserve = argv[++i] ;
			}
			else if( strcmp( argv[i] , "--server-no" ) == 0 && i + 1 < argc )
			{
				p_env->p_server_no = argv[++i] ;
			}
			else if( strcmp( argv[i] , "--limit-amt" ) == 0 && i + 1 < argc )
			{
				p_env->p_limit_amt = argv[++i] ;
			}
			else if( strcmp( argv[i] , "--export-jnls-amt-pathfilename" ) == 0 && i + 1 < argc )
			{
				p_env->p_export_jnls_amt_pathfilename = argv[++i] ;
			}
		}
		
		if( p_env->log_level == 0 )
		{
			p_env->log_level = LOGLEVEL_WARN ;
		}
		
		if( p_env->listen_port < 0 )
		{
			printf( "Invalid command parameter 'listen_port'\n" );
			usage();
			exit(7);
		}
		
		if( p_env->processor_count == 0 )
			p_env->processor_count = 1 ;
		else if( p_env->processor_count == -1 )
			p_env->processor_count = sysconf(_SC_NPROCESSORS_ONLN) ;
		else if( p_env->processor_count <= 0 )
		{
			printf( "Invalid command parameter 'processor_count'\n" );
			usage();
			exit(7);
		}
		
		if( p_env->app_mode == APPMODE_GLOBAL_SEQUENCE_SERVICE )
		{
			if( p_env->p_reserve == NULL || p_env->p_server_no == NULL )
			{
				printf( "expect parameter '--reserve (reserve)' or '--server-no (server_no)' for -M SEQUENCE\n" );
				return -1;
			}
			
			p_global_sequence_service->reserve = (uint64_t)atoi(p_env->p_reserve) ;
			p_global_sequence_service->server_no = (uint64_t)atoi(p_env->p_server_no) ;
		}
		else if( p_env->app_mode == APPMODE_GLOBAL_LIMITAMT_SERVICE )
		{
			if( p_env->p_limit_amt == NULL || p_env->p_export_jnls_amt_pathfilename == NULL )
			{
				printf( "expect parameter '--limit-amt (limit_amt)' or '--export-jnls-amt-pathfilename (export_jnls_amt_pathfilename)' for -M LIMITAMT\n" );
				return -1;
			}
			
			p_global_limitamt_service->limit_amt = (uint64_t)atoll(p_env->p_limit_amt) ;
			p_global_limitamt_service->export_jnls_amt_pathfilename = p_env->p_export_jnls_amt_pathfilename ;
			
			p_env->processor_count = 1 ;
		}
		
		/* �������й����ڴ� */
		p_env->data_space_shm.shmkey = 0 ;
		if( p_env->app_mode == APPMODE_GLOBAL_SEQUENCE_SERVICE )
			p_env->data_space_shm.size = sizeof(struct SerialShareMemory) ;
		else if( p_env->app_mode == APPMODE_GLOBAL_LIMITAMT_SERVICE )
			p_env->data_space_shm.size = sizeof(struct JnlsnoShareMemory) ;
		p_env->data_space_shm.shmid = shmget( p_env->data_space_shm.shmkey , p_env->data_space_shm.size , IPC_CREAT|0644 ) ;
		if( p_env->data_space_shm.shmid == -1 )
		{
			printf( "shmget failed , errno[%d]\n" , errno );
			return 1;
		}
		
		/* �������й����ڴ� */
		p_env->data_space_shm.base = shmat( p_env->data_space_shm.shmid , NULL , 0 ) ;
		if( p_env->data_space_shm.base == NULL )
		{
			printf( "shmat failed , errno[%d]\n" , errno );
			return 1;
		}
		memset( p_env->data_space_shm.base , 0x00 , p_env->data_space_shm.size );
		if( p_env->app_mode == APPMODE_GLOBAL_SEQUENCE_SERVICE )
			p_global_sequence_service->p_serial_shm = (struct SerialShareMemory *)(p_env->data_space_shm.base) ;
		else if( p_env->app_mode == APPMODE_GLOBAL_LIMITAMT_SERVICE )
			p_global_limitamt_service->p_jnlsno_shm = (struct JnlsnoShareMemory *)(p_env->data_space_shm.base) ;
		
		if( p_env->app_mode == APPMODE_GLOBAL_SEQUENCE_SERVICE )
		{
			/* ��ʼ�����к�ǰ��� */
			nret = InitSequence( & env ) ;
		}
		else if( p_env->app_mode == APPMODE_GLOBAL_LIMITAMT_SERVICE )
		{
			/* ��ʼ����� */
			nret = InitLimitAmt( & env ) ;
		}
		if( nret != HTTP_OK )
		{
			printf( "init failed[%d] , errno[%d]\n" , nret , errno );
			return 1;
		}
		
		/* �������пͻ��˻Ự����ṹ���� */
		memset( & (p_env->accepted_session_array_list) , 0x00 , sizeof(struct AcceptedSessionArray) );
		INIT_LIST_HEAD( & (p_env->accepted_session_array_list.prealloc_node) );
		
		/* �������пͻ��˻Ự�ṹ���� */
		memset( & (p_env->accepted_session_unused_list) , 0x00 , sizeof(struct AcceptedSession) );
		INIT_LIST_HEAD( & (p_env->accepted_session_unused_list.unused_node) );
		
		/* Ԥ���������ӻỰ�ռ� */
		IncreaseAcceptedSessions( & env );
		
		/* ��ʼ��tcpdaemon�����ṹ */
		memset( & para , 0x00 , sizeof(struct TcpdaemonEntryParameter) );
		para.daemon_level = 1 ;
		snprintf( para.log_pathfilename , sizeof(para.log_pathfilename)-1 , "%s/log/coconut.log" , getenv("HOME") );
		para.log_level = p_env->log_level ;
		strcpy( para.server_model , "IOMP" );
		para.timeout_seconds = 60 ;
		para.process_count = p_env->processor_count ;
		strcpy( para.ip , p_env->listen_ip );
		para.port = p_env->listen_port ;
		para.pfunc_tcpmain = & tcpmain ;
		para.param_tcpmain = & env ;
		para.tcp_nodelay = 1 ;
		para.cpu_affinity = p_env->cpu_affinity ;
		
		/* ����tcpdaemon���� */
		nret = tcpdaemon( & para ) ;
		if( nret )
		{
			printf( "call tcpdaemon failed[%d] , errno[%d]\n" , nret , errno );
		}
		
		/* �Ͽ������ڴ� */
		shmdt( p_env->data_space_shm.base );
		
		/* ɾ�������ڴ� */
		shmctl( p_env->data_space_shm.shmid , IPC_RMID , NULL );
		
		/* �ͷ������ӻỰ�ռ� */
		FreeAllAcceptedSessionArray( p_env );
	}
	else
	{
		usage();
		exit(7);
	}
	
	return 0;
}
