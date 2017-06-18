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
 * 以下为 全局流水号发生器
 */

/* 对外提供获取序列号URI */
#define URI_FETCH		"/fetch"
/* 对外提供解释序列号URI */
#define URI_EXPLAIN__SEQUENCE	"/explain?sequence="

/* 六十四进位制字符集 */
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
 * 以下为 全局额度管理器
 */

/* 查询额度 */
#define URI_QUERY		"/query"
/* 申请额度 */
#define URI_APPLY__AMT		"/apply?amt="
/* 撤消流水 */
#define URI_CANCEL__JNLSNO	"/cancel?jnlsno="
/* 补充额度 */
#define URI_INCREASE__AMT	"/increase?amt="
/* 扣减额度 */
#define URI_DECREASE__AMT	"/decrease?amt="
/* 清空额度 */
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
 * 以下为 公共定义
 */

/* 通讯基础信息结构 */
struct NetAddress
{
	char			ip[ 20 + 1 ] ;
	int			port ;
	SOCKET			sock ;
	struct sockaddr_in	addr ;
} ;

/* 客户端连接会话结构 */
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

/* 共享内存信息结构 */
struct ShareMemory
{
	int			proj_id ; /* 用于计算共享内存key的ftok参数 */
	key_t			shmkey ; /* 共享内存key */
	int			shmid ; /* 共享内存sequence_buffer */
	void			*base ; /* 共享内存连接基地址 */
	int			size ; /* 共享内存大小 */
} ;

/* 额度分配流水明细块 */

#define APPMODE_GLOBAL_SEQUENCE_SERVICE	1
#define APPMODE_GLOBAL_LIMITAMT_SERVICE	2

#define JNLSDETAILSCOUNT_IN_BLOCK	1000

/* 服务端环境结构 */
struct CoconutServerEnvironment
{
	char			listen_ip[ 20 + 1 ] ; /* 侦听IP */
	int			listen_port ; /* 侦听端口 */
	int			processor_count ; /* 并发数量 */
	int			log_level ; /* 日志等级 */
	char			*p_reserve ; /* 保留值 */
	char			*p_server_no ; /* 服务器编号 */
	char			*p_limit_amt ; /* 额度配置值 */
	char			*p_export_jnls_amt_pathfilename ; /* 最后输出申请额度流水明细文件名 */
	int			cpu_affinity ;
	
	struct ShareMemory	data_space_shm ; /* 共享内存系统参数 */
	int			app_mode ; /* 应用模式 */
	
	struct AcceptedSessionArray	accepted_session_array_list ;
	struct AcceptedSession		accepted_session_unused_list ;
	
	union
	{
		struct GlobalSequenceService
		{
			/* 以下为 全局流水号发生器 */
			uint64_t			reserve ; /* 保留值 */
			uint64_t			server_no ; /* 服务器编号 */
			char				sequence_buffer[ 16 + 1 ] ; /* 序列号输出缓冲区 */
			char				output_buffer[ 128 + 1 ] ; /* 输出缓冲区 */
			int				output_buffer_len ; /* 输出缓冲区有效长度 */
			struct SerialShareMemory
			{
				uint64_t		serial_no ; /* 序号 */
			} *p_serial_shm ; /* 共享内存指针 */
		} global_sequence_service ;
		
		struct GlobalLimitAmtService
		{
			/* 以下为 全局额度管理器 */
			int64_t				limit_amt ; /* 额度配置值 */
			char				*export_jnls_amt_pathfilename ; /* 最后输出申请额度流水明细文件名 */
			char				in_apply_flag ; /* 可申请额度标志 */
			char				output_buffer[ 128 + 1 ] ; /* 输出缓冲区 */
			int				output_buffer_len ; /* 输出缓冲区有效长度 */
			
			struct JnlsnoShareMemory
			{
				uint64_t		jnls_no ; /* 明细流水号 */
				int64_t			limit_amt ; /* 当前额度 */
			} *p_jnlsno_shm ; /* 共享内存指针 */
			
			struct JnlsDetailsBlock
			{
				struct JnlsDetails
				{
					uint64_t	jnls_no ; /* 明细流水号 */
					int64_t		amt ; /* 申请额度 */
					unsigned char	valid ; /* 有效性 */
					uint64_t	cancel_jnls_no ; /* 明细流水号 */
				} jnls_details[ JNLSDETAILSCOUNT_IN_BLOCK ] ;
				int			jnls_details_count ; /* 块内有效明细数量 */
				
				struct list_head	prealloc_node ; /* 块链表节点 */
			} jnls_details_blocks , *p_current_jnls_details_blocks ; /* 申请额度流水明细块 */
		} global_limitamt_service ;
	} app_data ;
} ;

/* 从NetAddress中设置、得到IP、PORT宏 */
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

/* 初始化序列号前半段 */
static int InitSequence( struct CoconutServerEnvironment *p_env )
{
	struct GlobalSequenceService	*p_global_sequence_service = & (p_env->app_data.global_sequence_service) ;
	uint64_t			index_region ;
	uint64_t			reserve_region_length = 1 ;
	uint64_t			server_no_region_length = 2 ;
	uint64_t			secondstamp_region_length = 6 ;
	uint64_t			serial_no_region_length = 5 ;
	
	/* 初始化序号 */
	p_global_sequence_service->p_serial_shm->serial_no = 1 ;
	
	/*
	第一区 分区目录 2个六十四进制字符 共12个二进制位
			第一段3个二进制位表示保留区六十四进制字符个数
			第二段3个二进制位表示服务器编号区六十四进制字符个数
			第三段3个二进制位表示秒戳区六十四进制字符个数
			第四段3个二进制位表示序号区六十四进制字符个数
	第二区 保留区 1个六十四进制字符 有6个二进制位可用
	第三区 服务器编号区 2个六十四进制字符 可表示4096台发起器服务器
	第四区 秒戳区 6个六十四进制字符 可表示2179年的秒戳
	第五区 序号区 5个六十四进制字符 序号区间[1,10亿]
			共16个六十四进制字符
	*/
	
	/* 分区目录 */
	index_region = (reserve_region_length<<9) + (server_no_region_length<<6) + (secondstamp_region_length<<3) + (serial_no_region_length) ;
	p_global_sequence_service->sequence_buffer[0] = sg_64_scale_system_charset[(index_region>>6)&0x3F] ;
	p_global_sequence_service->sequence_buffer[1] = sg_64_scale_system_charset[index_region&0x3F] ;
	
	/* 保留区 */
	p_global_sequence_service->sequence_buffer[2] = sg_64_scale_system_charset[p_global_sequence_service->reserve&0x3F] ;
	
	/* 服务器编号区 */
	p_global_sequence_service->sequence_buffer[3] = sg_64_scale_system_charset[(p_global_sequence_service->server_no>>6)&0x3F] ;
	p_global_sequence_service->sequence_buffer[4] = sg_64_scale_system_charset[p_global_sequence_service->server_no&0x3F] ;
	
	return HTTP_OK;
}
		
/* 获取序列号 */
static int FetchSequence( struct CoconutServerEnvironment *p_env )
{
	struct GlobalSequenceService	*p_global_sequence_service = & (p_env->app_data.global_sequence_service) ;
	uint64_t			secondstamp ;
	uint64_t			ret_serial_no ;
	
	/* 秒戳区 */
	secondstamp = time( NULL );
	p_global_sequence_service->sequence_buffer[5] = sg_64_scale_system_charset[(secondstamp>>30)&0x3F] ;
	p_global_sequence_service->sequence_buffer[6] = sg_64_scale_system_charset[(secondstamp>>24)&0x3F] ;
	p_global_sequence_service->sequence_buffer[7] = sg_64_scale_system_charset[(secondstamp>>18)&0x3F] ;
	p_global_sequence_service->sequence_buffer[8] = sg_64_scale_system_charset[(secondstamp>>12)&0x3F] ;
	p_global_sequence_service->sequence_buffer[9] = sg_64_scale_system_charset[(secondstamp>>6)&0x3F] ;
	p_global_sequence_service->sequence_buffer[10] = sg_64_scale_system_charset[secondstamp&0x3F] ;
	
	/* 序号区 */
	ret_serial_no = __sync_fetch_and_add( & (p_global_sequence_service->p_serial_shm->serial_no) , 1 ) ; /* 序号自增一 */
	p_global_sequence_service->sequence_buffer[11] = sg_64_scale_system_charset[(ret_serial_no>>24)&0x3F] ;
	p_global_sequence_service->sequence_buffer[12] = sg_64_scale_system_charset[(ret_serial_no>>18)&0x3F] ;
	p_global_sequence_service->sequence_buffer[13] = sg_64_scale_system_charset[(ret_serial_no>>12)&0x3F] ;
	p_global_sequence_service->sequence_buffer[14] = sg_64_scale_system_charset[(ret_serial_no>>6)&0x3F] ;
	p_global_sequence_service->sequence_buffer[15] = sg_64_scale_system_charset[ret_serial_no&0x3F] ;
	
	return HTTP_OK;
}

/* 解释序列号 */
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

/* 导出额度流水明细 */
static int ExportJnlsAmtDetails( struct CoconutServerEnvironment *p_env )
{
	struct GlobalLimitAmtService	*p_global_limitamt_service = & (p_env->app_data.global_limitamt_service) ;
	pid_t				pid ;
	FILE				*fp = NULL ;
	struct JnlsDetailsBlock		*p_jnls_details_block = NULL ;
	int				i ;
	
	/* 设置信号句柄 */
	signal( SIGCHLD , SIG_IGN );
	
	/* 创建子进程 */
	pid = fork() ;
	if( pid == -1 )
		return -1;
	else if( pid > 0 )
		return 0;
	
	/* 导出流水明细 */
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

/* 初始化额度 */
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
	
	/* 测试输出文件 */
	fp = fopen( p_global_limitamt_service->export_jnls_amt_pathfilename , "w" ) ;
	if( fp == NULL )
	{
		printf( "can't write file[%s]\n" , p_global_limitamt_service->export_jnls_amt_pathfilename );
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	fclose( fp );
	
	return HTTP_OK;
}

/* 查询当前额度 */
static int QueryCurrentLimitAmt( struct CoconutServerEnvironment *p_env )
{
	struct GlobalLimitAmtService	*p_global_limitamt_service = & (p_env->app_data.global_limitamt_service) ;
	
	p_global_limitamt_service->output_buffer_len = snprintf( p_global_limitamt_service->output_buffer , sizeof(p_global_limitamt_service->output_buffer)-1 , "%"PRId64"\n" , p_global_limitamt_service->p_jnlsno_shm->limit_amt ) ;
	return HTTP_OK;
}

/* 申请额度 */
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

/* 撤销额度 */
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

/* 补充当前额度 */
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

/* 扣减当前额度 */
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

/* 清空当前额度 */
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

/* 应用层处理 */
static int DispatchProcess( struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	char			*uri = NULL ;
	int			uri_len ;
	
	int			nret = 0 ;
	
	/* 得到URI */
	uri = GetHttpHeaderPtr_URI( p_accepted_session->http , & uri_len ) ;
	INFOLOG(  "uri[%.*s]" , uri_len , uri );
	
	if( p_env->app_mode == APPMODE_GLOBAL_SEQUENCE_SERVICE )
	{
		struct GlobalSequenceService	*p_global_sequence_service = & (p_env->app_data.global_sequence_service) ;
		
		/* 获取序列号 */
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
		/* 解释序列号 */
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
		
		/* 查询当前额度 */
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
		/* 申请额度 */
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
		/* 撤销额度 */
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
		/* 补充当前额度 */
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
		/* 扣减当前额度 */
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
		/* 清空当前额度 */
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

/* 预分配空闲客户端会话结构 */
static int IncreaseAcceptedSessions( struct CoconutServerEnvironment *p_env )
{
	struct AcceptedSessionArray	*p_accepted_session_array = NULL ;
	struct AcceptedSession		*p_accepted_session = NULL ;
	int				i ;
	
	/* 批量增加空闲HTTP通讯会话 */
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

/* 从预分配的空闲客户端会话结构中取出一个 */
static struct AcceptedSession *FetchAcceptedSessionUnused( struct CoconutServerEnvironment *p_env )
{
	struct AcceptedSession	*p_accepted_session = NULL ;
	
	int			nret = 0 ;
	
	/* 如果空闲客户端会话链表为空 */
	if( list_empty( & (p_env->accepted_session_unused_list.unused_node) ) )
	{
		nret = IncreaseAcceptedSessions( p_env ) ;
		if( nret )
			return NULL;
	}
	
	/* 从空闲HTTP通讯会话链表中移出一个会话，并返回之 */
	p_accepted_session = list_first_entry( & (p_env->accepted_session_unused_list.unused_node) , struct AcceptedSession , unused_node ) ;
	list_del( & (p_accepted_session->unused_node) );
	
	DebugLog( __FILE__ , __LINE__ , "fetch accepted session[%p]" , p_accepted_session );
	ResetHttpEnv( p_accepted_session->http );
	return p_accepted_session;
}

/* 把当前客户端会话放回空闲链表中去 */
static void SetAcceptedSessionUnused( struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	DebugLog( __FILE__ , __LINE__ , "putback accepted session[%p]" , p_accepted_session );
	
	/* 把当前工作HTTP通讯会话移到空闲HTTP通讯会话链表中 */
	list_add_tail( & (p_accepted_session->unused_node) , & (p_env->accepted_session_unused_list.unused_node) );
	
	return;
}

/* 销毁所有客户端物理会话结构 */
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

/* 处理接受新连接事件 */
static int OnAcceptingSocket( struct TcpdaemonServerEnvironment *p , struct CoconutServerEnvironment *p_env , int sock , struct sockaddr *p_addr )
{
	struct AcceptedSession	*p_accepted_session = NULL ;
	
	/* 申请内存以存放已连接会话 */
	p_accepted_session = FetchAcceptedSessionUnused( p_env ) ;
	if( p_accepted_session == NULL )
		return TCPMAIN_RETURN_ERROR;
	
	p_accepted_session->netaddr.sock = sock ;
	memcpy( & (p_accepted_session->netaddr.addr) , & p_addr , sizeof(struct sockaddr) );
	
	/* 设置已连接会话数据结构 */
	TDSetIoMultiplexDataPtr( p , p_accepted_session );
	
	/* 等待读事件 */
	return TCPMAIN_RETURN_WAITINGFOR_RECEIVING;
}

/* 主动关闭套接字 */
static int OnClosingSocket( struct TcpdaemonServerEnvironment *p , struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	/* 释放已连接会话 */
	INFOLOG(  "close session[%d]" , p_accepted_session->netaddr.sock );
	
	SetAcceptedSessionUnused( p_env , p_accepted_session );
	
	/* 等待下一任意事件 */
	return TCPMAIN_RETURN_WAITINGFOR_NEXT;
}

/* 接收客户端套接字数据 */
static int OnReceivingSocket( struct TcpdaemonServerEnvironment *p , struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	int			nret = 0 ;
	
	/* 接收请求数据 */
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
		/* 接收完整了 */
		DEBUGLOG(  "ReceiveHttpRequestNonblock[%d] return DONE" , p_accepted_session->netaddr.sock );
		
		/* 调用应用层 */
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

/* 发送客户端套接字数据 */
static int OnSendingSocket( struct TcpdaemonServerEnvironment *p , struct CoconutServerEnvironment *p_env , struct AcceptedSession *p_accepted_session )
{
	int			nret = 0 ;
	
	/* 发送响应数据 */
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
		
		/* 解析命令行参数 */
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
		
		/* 创建序列共享内存 */
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
		
		/* 连接序列共享内存 */
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
			/* 初始化序列号前半段 */
			nret = InitSequence( & env ) ;
		}
		else if( p_env->app_mode == APPMODE_GLOBAL_LIMITAMT_SERVICE )
		{
			/* 初始化额度 */
			nret = InitLimitAmt( & env ) ;
		}
		if( nret != HTTP_OK )
		{
			printf( "init failed[%d] , errno[%d]\n" , nret , errno );
			return 1;
		}
		
		/* 创建空闲客户端会话物理结构链表 */
		memset( & (p_env->accepted_session_array_list) , 0x00 , sizeof(struct AcceptedSessionArray) );
		INIT_LIST_HEAD( & (p_env->accepted_session_array_list.prealloc_node) );
		
		/* 创建空闲客户端会话结构链表 */
		memset( & (p_env->accepted_session_unused_list) , 0x00 , sizeof(struct AcceptedSession) );
		INIT_LIST_HEAD( & (p_env->accepted_session_unused_list.unused_node) );
		
		/* 预分配已连接会话空间 */
		IncreaseAcceptedSessions( & env );
		
		/* 初始化tcpdaemon参数结构 */
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
		
		/* 调用tcpdaemon引擎 */
		nret = tcpdaemon( & para ) ;
		if( nret )
		{
			printf( "call tcpdaemon failed[%d] , errno[%d]\n" , nret , errno );
		}
		
		/* 断开共享内存 */
		shmdt( p_env->data_space_shm.base );
		
		/* 删除共享内存 */
		shmctl( p_env->data_space_shm.shmid , IPC_RMID , NULL );
		
		/* 释放已连接会话空间 */
		FreeAllAcceptedSessionArray( p_env );
	}
	else
	{
		usage();
		exit(7);
	}
	
	return 0;
}
