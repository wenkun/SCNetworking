//
//  SCNetworking.h
//  SCNetworking
//
//  Created by  伯波 李 on 2018/2/7.
//  Copyright © 2018年  伯波 李. All rights reserved.
//

#import <Foundation/Foundation.h>


#pragma mark - 定义
//文件上传进度监听key
#define UploadFileProgressNotifyKey @"UploadFileProgressNotifyKey"
#define SC_SAFE_BLOCK(BlockName, ...) ({ !BlockName ? nil : BlockName(__VA_ARGS__); })

#define SecurityLevel 2  //1:任何证书的HTTPS  2：校验服务器证书

typedef void (^SCBatchRequestConfigBlock)(NSMutableURLRequest *  batchRequest);


#pragma mark - 类
@interface SCNetworking : NSObject<NSURLSessionDataDelegate>


@property(nonatomic,strong)NSURLSession*  customSession;
@property(nonatomic,assign)BOOL logTag;
@property(nonatomic,retain)NSString* trustDomain;
@property(nonatomic,retain)NSDictionary* publicHeader;


//单例 用于用户自定义操作
+(SCNetworking*)shareInstance;

#pragma mark 配置

/**
 配置公共header

 @param header 请求头
 */
+(void)setPublicHeader:(NSDictionary*)header;

/**
 配置HTTPS自有证书
 
 @param caPath 证书路径
 */
+(void)configHTTPSCertificateWith:(NSString*)caPath;


/**
 设置客户端证书

 @param clientPath 证书路径
 @param pw 密码
 */
+(void)configHTTPSClientCertificateWith:(NSString*)clientPath Password:(NSString*)pw;

#pragma mark 请求方法
#pragma mark - upload

/**
 上传文件
 
 @param urlStr 网址
 @param headerDic header
 @param paramDic 参数
 @param fpaths 文件详情 @[@{@"fileName":@"",@"contentType":@"",@"data":nsdata}]
 @param success 成功返回
 @param failed 失败返回
 @return 任务对象
 */
+(NSURLSessionUploadTask*)upload:(NSString*)urlStr header:(NSDictionary *)headerDic parameters:(NSDictionary *)paramDic fileDetail:(NSArray*)fpaths completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;

#pragma mark - post
/**
 post请求
 
 @param urlStr 请求地址
 @param headerDic 请求头
 @param paramDic 请求体参数
 @param success 成功返回
 @param failed 失败返回
 */
+(NSURLSessionDataTask *)post:(NSString*)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary*)paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;

+(NSURLSessionDataTask *)post:(SCBatchRequestConfigBlock)batchBlock completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;

/**
 application/x-www-form-urlencoded;charset=utf-8格式的post请求
 
 @param urlStr 请求地址
 @param headerDic 请求头
 @param paramDic 请求体参数
 @param success 成功返回
 @param failed 失败返回
 @return NSURLSessionDataTask
 */
+(NSURLSessionDataTask *)postWithFormEncode:(NSString*)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary*)paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;
/**
 multipart/form-data格式的post请求

 @param urlStr 请求地址
 @param headerDic 请求头
 @param paramDic 请求体参数
 @param success 成功返回
 @param failed 失败返回
 @return NSURLSessionDataTask
 */
+(NSURLSessionDataTask *)postOfFormdata:(NSString*)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary*)paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;

/**
 multipart/form-data格式的post请求
 
 @param urlStr 请求地址
 @param headerDic 请求头
 @param paramDic 请求体参数{key:{@"contentType":@"",@"value":@"",@"fileName":@""}}
 @param success 成功返回
 @param failed 失败返回
 @return NSURLSessionDataTask
 */
+(NSURLSessionDataTask *)postFormdataWithMutableType:(NSString*)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary*)paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;

#pragma mark - get
/**
 get请求

 @param urlStr 请求地址
 @param headerDic 请求头
 @param paramDic 请求体参数
 @param success 成功返回
 @param failed 失败返回
 */
+(NSURLSessionDataTask *)get:(NSString *)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary* )paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;

+(NSURLSessionDataTask *)get:(SCBatchRequestConfigBlock)batchBlock completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;

//返回的数据不做处理
+(NSURLSessionDataTask *)getRawDataFrom:(NSString *)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary* )paramDic completionSuccess:(void (^)(NSURLResponse *response, NSData *data))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;

#pragma mark - put
/**
 put请求
 
 @param urlStr 请求地址
 @param headerDic 请求头
 @param paramDic 请求体参数
 @param success 成功返回
 @param failed 失败返回
 */
+(NSURLSessionDataTask *)put:(NSString *)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary* )paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;

+(NSURLSessionDataTask *)put:(SCBatchRequestConfigBlock)batchBlock completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;

/**
 上传文件

 @param urlStr 网址
 @param headerDic header
 @param paramDic 参数
 @param success 成功返回
 @param failed 失败返回
 @return 任务对象
 */
+(NSURLSessionUploadTask*)uploadPutWith:(NSString*)urlStr header:(NSDictionary *)headerDic parameters:(NSDictionary *)paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;

#pragma mark - patch
/**
 patch请求
 
 @param urlStr 请求地址
 @param headerDic 请求头
 @param paramDic 请求体参数
 @param success 成功返回
 @param failed 失败返回
 */
+(NSURLSessionDataTask *)patch:(NSString *)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary* )paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;

+(NSURLSessionDataTask *)patch:(SCBatchRequestConfigBlock)batchBlock completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;



#pragma mark -

//创建NSURLSessionDataTask
-(NSURLSessionDataTask*)createJsonDataTaskWith:(NSMutableURLRequest *)request completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;


@end
