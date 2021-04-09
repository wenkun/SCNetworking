//
//  SCNetworking.m
//  SCNetworking
//
//  Created by  伯波 李 on 2018/2/7.
//  Copyright © 2018年  伯波 李. All rights reserved.
//

#ifdef DEBUG
#define NetLog(FORMAT, ...) NSLog((FORMAT), ##__VA_ARGS__)
#else
#define NetLog(FORMAT, ...)
#endif

#ifndef __Require_noErr_Quiet
#define __Require_noErr_Quiet(errorCode, exceptionLabel)                      \
do                                                                          \
{                                                                           \
if ( __builtin_expect(0 != (errorCode), 0) )                            \
{                                                                       \
goto exceptionLabel;                                                \
}                                                                       \
} while ( 0 )
#endif

#ifndef __Require_Quiet
#define __Require_Quiet(assertion, exceptionLabel)                            \
do                                                                          \
{                                                                           \
if ( __builtin_expect(!(assertion), 0) )                                \
{                                                                       \
goto exceptionLabel;                                                \
}                                                                       \
} while ( 0 )
#endif

#ifndef __nRequire_Quiet
#define __nRequire_Quiet(assertion, exceptionLabel)  __Require_Quiet(!(assertion), exceptionLabel)
#endif

#import "SCNetworking.h"

#define RequestTimeoutInterval 15.f
#define Error_JSON @"JSON数据解析失败"

#define ContentTypeKey @"Content-type"
#define ContentType_ApplicationJson @"application/json;charset=UTF-8"


#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>

@interface SCNetworking ()
@property(nonatomic,retain)NSData *caData;
@property(nonatomic,retain)NSData *clientData;
@property(nonatomic,retain)NSString* clientPassword;
@property(nonatomic,retain)NSMutableDictionary* logDic;
@property(nonatomic,retain)NSMutableDictionary* requestTimeDic;
@property(nonatomic,retain)NSLock *logLock;
@end

@implementation SCNetworking


#pragma mark - 加密
/**
 md5加密
 
 @param str 要加密的字符串
 @return 加密后的字符串
 */
+(NSString *)getMD5From:(NSString *)str{
    const char *cStr = [str UTF8String];
    unsigned char result[16];
    CC_MD5(cStr, (CC_LONG)strlen(cStr), result); // This is the md5 call
    return [NSString stringWithFormat:
            @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            result[0], result[1], result[2], result[3],
            result[4], result[5], result[6], result[7],
            result[8], result[9], result[10], result[11],
            result[12], result[13], result[14], result[15]
            ];
}
#pragma mark 签名算法
+(NSString*)getSignFrom:(NSDictionary*)header HttpBody:(NSData*)body
{
    NSString* newSign = [SCNetworking getSignPlanTextFrom:header HttpBody:body];
    NSString* singMD5 = [SCNetworking getMD5From:newSign];
    return singMD5;
}
+(NSString*)getSignPlanTextFrom:(NSDictionary*)header HttpBody:(NSData*)body
{
    //client_id+app_key+body(JsonString)+timestamp+app_secret+v的顺序进行md5加密
    NSString* contentType = [header objectForKey:ContentTypeKey];
    
    BOOL isMutipartFormData = contentType&&[[contentType lowercaseString] containsString:@"multipart/form-data"];
    
    NSString*bodyStr = @"{}";
    if (isMutipartFormData==NO) {
        bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    }
    
    NSString* clientid = [header objectForKey:@"client_id"]?:@"";
    NSString* timeStamp = [header objectForKey:@"timestamp"]?:@"";
    NSString* appkey = [header objectForKey:@"app_key"]?:@"";
    NSString* appSecret = [header objectForKey:@"app_security"]?:@"";
    NSString* appV = [header objectForKey:@"v"]?:@"";
    
    NSString* sign = [NSString stringWithFormat:@"%@%@%@%@%@%@",clientid,appkey,bodyStr,timeStamp,appSecret,appV];
    NSString* newSign = [sign stringByReplacingOccurrencesOfString:@" " withString:@""];
    newSign = [newSign stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    newSign = [newSign stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    return newSign;
}
#pragma mark - 初始化
+(SCNetworking*)shareInstance
{
    static SCNetworking *sHttpMangerInstance;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        sHttpMangerInstance = [[SCNetworking alloc] init];
        [sHttpMangerInstance initData];
    });

    return sHttpMangerInstance;
}
-(void)initData
{
    self.logTag = NO;
    self.logLock = [[NSLock alloc] init];
    self.logDic = [[NSMutableDictionary alloc] init];
    self.requestTimeDic = [[NSMutableDictionary alloc] init];
    
    [self initCustomSession];
    
}
- (void)initCustomSession {
    if (_customSession == nil) {
        // session的配置信息
        NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
        
        // 请求的超时时长是1秒
        config.timeoutIntervalForRequest = RequestTimeoutInterval;
        config.requestCachePolicy = NSURLRequestUseProtocolCachePolicy;

        // 自定义session的同时设置代理
        _customSession = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:[[NSOperationQueue alloc] init]];
    }
}

#pragma mark log
-(void)printRequest:(NSURLRequest*)request withHeader:(NSDictionary*)header withParamter:(NSDictionary*)parater
{
    if (self.logTag) {
        NSString* logStr = @"";
//#if DEBUG
//#else
//        header = @{@"keep header secret":@"keep header secret!!!"};
//#endif
        if ([header objectForKey:@"sign"] == nil) {
        NSString* newSign = [SCNetworking getSignPlanTextFrom:header HttpBody:request.HTTPBody];

        logStr = [NSString stringWithFormat:@"\n#############SCNetworking STRAT*#############\n\n%@\n============= Header =============\n%@\n============= Paramter =============\n%@\n签名明文：%@",request?:@"",header?:@"",parater?:@"",newSign?:@""];
        }
        else
        {
            logStr = [NSString stringWithFormat:@"\n#############SCNetworking STRAT#############\n\n%@\n============= Header =============\n%@\n============= Paramter =============\n%@\n",request?:@"",header?:@"",parater?:@""];
        }
        if (request) {
            [self.logLock lock];
            [self.logDic setObject:logStr forKey:request];
            [self.logLock unlock];
        }
    }
}
- (NSString *)stringByReplaceUnicode:(NSString *)unicodeString
{
    if(unicodeString==nil||unicodeString.length==0||[unicodeString isKindOfClass:[NSString class]]==NO)
    {
        return @"";
    }
    else
    {
        NSMutableString *convertedString = [unicodeString mutableCopy];
        [convertedString replaceOccurrencesOfString:@"\\U" withString:@"\\u" options:0 range:NSMakeRange(0, convertedString.length)];
        CFStringRef transform = CFSTR("Any-Hex/Java");
        CFStringTransform((__bridge CFMutableStringRef)convertedString, NULL, transform, YES);
        
        return convertedString;
    }
}

-(void)printResponse:(NSURLResponse*)response request:(NSURLRequest*)request withData:(NSDictionary*)data withError:(NSError*)error
{
    if (self.logTag) {
        NSString* logStr = [[NSString stringWithFormat:@"*************SCNetworking Response*************\n\n%@\n============= Data =============\n%@",response?:@"",[[data description] stringByRemovingPercentEncoding]?:@""] stringByRemovingPercentEncoding];

        NSString* endStr = @"";
        if (error) {
            endStr = [NSString stringWithFormat:@"============= Error =============\n%@",error];
        }
        endStr = [NSString stringWithFormat:@"%@\n#############SCNetworking END#############",endStr];
        [self.logLock lock];
        NSString*startLog = [[self.logDic objectForKey:request] stringByRemovingPercentEncoding];
        startLog = [self stringByReplaceUnicode:startLog];
        logStr = [self stringByReplaceUnicode:logStr];
//        printf("%s\n%s\n%s",[startLog  UTF8String],[logStr UTF8String],[endStr UTF8String]);
        NSLog(@"[SCNetworking] %s",[startLog UTF8String]);
        NSLog(@"[SCNetworking] %s",[logStr UTF8String]);
        NSLog(@"[SCNetworking] %s",[endStr UTF8String]);
        
        NSDate *beginDate = [self.requestTimeDic objectForKey:request];
        if (beginDate) {
            NSLog(@"[SCNetworking] KeepTime:%f -[%@]", [[NSDate date] timeIntervalSinceDate:beginDate], request.URL);
            [self.requestTimeDic removeObjectForKey:request];
        }
        [self.logLock unlock];
    }
}


#pragma mark - NSURLSession代理
#pragma mark NSURLSessionDataDelegate
/**
 *  监听进度
 *
 *  @param bytesSent 本次发送的字节数
 *  @param totalBytesSent       总共发送的字节数
 *  @param totalBytesExpectedToSend       文件的总大小
 *
 */
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
   didSendBodyData:(int64_t)bytesSent
    totalBytesSent:(int64_t)totalBytesSent
totalBytesExpectedToSend:(int64_t)totalBytesExpectedToSend {
    
    // 计算进度
    float progress = (float)totalBytesSent / totalBytesExpectedToSend;
    if (task.taskDescription) {
        NSLog(@"[SCNetworking] 上传文件%@进度 %f",task.taskDescription,progress);
        [[NSNotificationCenter defaultCenter] postNotificationName:UploadFileProgressNotifyKey object:nil userInfo:@{task.taskDescription:[NSNumber numberWithFloat:progress]}];
    }
}
#pragma mark NSURLSessionDelegate
- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler
{
    NetLog(@"didReceiveChallenge ");
    
    NSURLSessionAuthChallengeDisposition disposition = NSURLSessionAuthChallengePerformDefaultHandling;
    NSURLCredential *credential = nil;
    
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        NetLog(@"server ---------");

        NSString *host = challenge.protectionSpace.host;
        NetLog(@"%@", host);
        
        if (SecurityLevel==1) {
            SecTrustRef trust = challenge.protectionSpace.serverTrust;
            //方案1：系统方法验证
            NSMutableArray *certificates = [NSMutableArray array];
            NSData *cerData = [NSData dataWithData:self.caData];/* 在 App Bundle 中你用来做锚点的证书数据，证书是 CER 编码的，常见扩展名有：cer, crt...*/
            SecCertificateRef cerRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)cerData);
            [certificates addObject:(__bridge_transfer id)cerRef];
            
            // 设置锚点证书。
            SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)certificates);
            // true 代表仅被传入的证书作为锚点，false 允许系统 CA 证书也作为锚点
            SecTrustSetAnchorCertificatesOnly(trust, false);
            credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
            if (credential) {
                disposition = NSURLSessionAuthChallengeUseCredential;
            }
        }
        else if(SecurityLevel == 2)
        {
            /* 调用自定义的验证过程 */
            if ([self myCustomValidation:challenge]) {
                
                credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
                if (credential) {
                    disposition = NSURLSessionAuthChallengeUseCredential;
                    NSLog(@"[sss] disposition NSURLSessionAuthChallengeUseCredential");
                }
            } else {
                /* 无效的话，取消 */
                disposition = NSURLSessionAuthChallengeCancelAuthenticationChallenge;
                
                NSLog(@"[sss] disposition 无效");
            }
        }
        else
        {
            disposition = NSURLSessionAuthChallengeCancelAuthenticationChallenge;
        }
    }
    else if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate])
    {
        //客户端证书认证
        //TODO:设置客户端证书认证
        // load cert
        
        NSData *p12data = self.clientData;
        
        if (p12data!=nil) {
            CFDataRef inP12data = (__bridge CFDataRef)p12data;
            SecIdentityRef myIdentity;
            OSStatus status = [self extractIdentity:inP12data toIdentity:&myIdentity];
            if (status != 0) {
                return;
            }
            SecCertificateRef myCertificate;
            SecIdentityCopyCertificate(myIdentity, &myCertificate);
            const void *certs[] = { myCertificate };
            CFArrayRef certsArray =CFArrayCreate(NULL, certs,1,NULL);
            NSArray* certsNSArray = CFBridgingRelease(certsArray);
            credential = [NSURLCredential credentialWithIdentity:myIdentity certificates:certsNSArray persistence:NSURLCredentialPersistencePermanent];

            if (credential) {
                disposition = NSURLSessionAuthChallengeUseCredential;
            }
        }
    }
    if (completionHandler) {
        completionHandler(disposition, credential);
    }
}
static NSArray * AFCertificateTrustChainForServerTrust(SecTrustRef serverTrust) {
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray *trustChain = [NSMutableArray arrayWithCapacity:(NSUInteger)certificateCount];
    
    for (CFIndex i = 0; i < certificateCount; i++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        [trustChain addObject:(__bridge_transfer NSData *)SecCertificateCopyData(certificate)];
    }
    
    return [NSArray arrayWithArray:trustChain];
}
static NSArray * AFPublicKeyTrustChainForServerTrust(SecTrustRef serverTrust) {
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray *trustChain = [NSMutableArray arrayWithCapacity:(NSUInteger)certificateCount];
    for (CFIndex i = 0; i < certificateCount; i++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        
        SecCertificateRef someCertificates[] = {certificate};
        CFArrayRef certificates = CFArrayCreate(NULL, (const void **)someCertificates, 1, NULL);
        
        SecTrustRef trust;
        __Require_noErr_Quiet(SecTrustCreateWithCertificates(certificates, policy, &trust), _out);
        
        SecTrustResultType result;
        __Require_noErr_Quiet(SecTrustEvaluate(trust, &result), _out);
        
        [trustChain addObject:(__bridge_transfer id)SecTrustCopyPublicKey(trust)];
        
    _out:
        if (trust) {
            CFRelease(trust);
        }
        
        if (certificates) {
            CFRelease(certificates);
        }
        
        continue;
    }
    CFRelease(policy);
    
    return [NSArray arrayWithArray:trustChain];
}
static id AFPublicKeyForCertificate(NSData *certificate) {
    id allowedPublicKey = nil;
    SecCertificateRef allowedCertificate;
    SecCertificateRef allowedCertificates[1];
    CFArrayRef tempCertificates = nil;
    SecPolicyRef policy = nil;
    SecTrustRef allowedTrust = nil;
    SecTrustResultType result;
    
    allowedCertificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificate);
    __Require_Quiet(allowedCertificate != NULL, _out);
    
    allowedCertificates[0] = allowedCertificate;
    tempCertificates = CFArrayCreate(NULL, (const void **)allowedCertificates, 1, NULL);
    
    policy = SecPolicyCreateBasicX509();
    __Require_noErr_Quiet(SecTrustCreateWithCertificates(tempCertificates, policy, &allowedTrust), _out);
    __Require_noErr_Quiet(SecTrustEvaluate(allowedTrust, &result), _out);
    
    allowedPublicKey = (__bridge_transfer id)SecTrustCopyPublicKey(allowedTrust);
    
_out:
    if (allowedTrust) {
        CFRelease(allowedTrust);
    }
    
    if (policy) {
        CFRelease(policy);
    }
    
    if (tempCertificates) {
        CFRelease(tempCertificates);
    }
    
    if (allowedCertificate) {
        CFRelease(allowedCertificate);
    }
    
    return allowedPublicKey;
}
static BOOL AFSecKeyIsEqualToKey(SecKeyRef key1, SecKeyRef key2) {
    return [(__bridge id)key1 isEqual:(__bridge id)key2];
}
-(BOOL)myCustomValidation:(NSURLAuthenticationChallenge *)challenge
{
    SecTrustRef trust = challenge.protectionSpace.serverTrust;
    
    CFArrayRef policiesRef;
    SecTrustCopyPolicies(trust, &policiesRef);
    
    NSMutableArray *policies = [NSMutableArray array];
    if (self.trustDomain) {
        [policies addObject:(__bridge_transfer id)SecPolicyCreateSSL(true, (__bridge CFStringRef)self.trustDomain)];
        SecTrustSetPolicies(trust, (__bridge CFArrayRef)policies);
    } else {
        // BasicX509 不验证域名是否相同
        [policies addObject:(__bridge_transfer id)SecPolicyCreateBasicX509()];
        SecTrustSetPolicies(trust, (__bridge CFArrayRef)policies);
        NSLog(@"[sss] BasicX509 不验证域名是否相同");
        // 需要验证域名，否则存在安全隐患
//        SecTrustSetPolicies(trust, policiesRef);
    }

    
    
    if (self.caData) {
        
        NSArray* serverCertificates = AFCertificateTrustChainForServerTrust(trust);
        NSArray *publicKeys = AFPublicKeyTrustChainForServerTrust(trust);
        
        //方案1：系统方法验证
        NSMutableArray *certificates = [NSMutableArray array];
        NSData *cerData = [NSData dataWithData:self.caData];/* 在 App Bundle 中你用来做锚点的证书数据，证书是 CER 编码的，常见扩展名有：cer, crt...*/
        SecCertificateRef cerRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)cerData);
        [certificates addObject:(__bridge_transfer id)cerRef];

        // 设置锚点证书。
        SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)certificates);
        // true 代表仅被传入的证书作为锚点，false 允许系统 CA 证书也作为锚点
        SecTrustSetAnchorCertificatesOnly(trust, false);
        
        if (serverTrustIsVaild(trust)) {
            return YES;
        }
        
        //方案2：证书验证
        NSUInteger trustedCertificateCount = 0;
        for (NSData *trustChainCertificate in serverCertificates) {
            if ([self.caData isEqualToData:trustChainCertificate]) {
                trustedCertificateCount++;
            }
        }
        if (trustedCertificateCount>0) {
            return YES;
        }
        
        
        //方案3：公开密钥验证
        NSUInteger trustedPublicKeyCount = 0;
        id publicKey = AFPublicKeyForCertificate(self.caData);
        for (id trustChainPublicKey in publicKeys) {
            if (AFSecKeyIsEqualToKey((__bridge SecKeyRef)trustChainPublicKey, (__bridge SecKeyRef)publicKey)) {
                trustedPublicKeyCount += 1;
            }
        }
        if (trustedPublicKeyCount>0) {
            return YES;
        }
    }
 
    
    return serverTrustIsVaild(trust);
}
static BOOL serverTrustIsVaild(SecTrustRef trust) {
    BOOL allowConnection = NO;
    
    // 假设验证结果是无效的
    SecTrustResultType trustResult = kSecTrustResultInvalid;
    
    // 函数的内部递归地从叶节点证书到根证书的验证
    OSStatus statue = SecTrustEvaluate(trust, &trustResult);
    
    if (statue == noErr) {
        // kSecTrustResultUnspecified: 系统隐式地信任这个证书
        // kSecTrustResultProceed: 用户加入自己的信任锚点，显式地告诉系统这个证书是值得信任的
        
        allowConnection = (trustResult == kSecTrustResultProceed
                           || trustResult == kSecTrustResultUnspecified);
        NSLog(@"[sss] statue == noErr");
    }
    else {
        NSLog(@"[sss] statue error");
    }
    return allowConnection;
}

- (OSStatus)extractIdentity:(CFDataRef)inP12Data toIdentity:(SecIdentityRef*)identity {
    OSStatus securityError = errSecSuccess;
    CFStringRef password = CFSTR("123456");
    if (self.clientPassword != nil&& self.clientPassword.length>0) {
        const char* pw = [self.clientPassword UTF8String];
        password = CFStringCreateWithCString(NULL,pw,kCFStringEncodingASCII);
    }
    
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { password };
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inP12Data, options, &items);
    if (securityError == 0)
    {
        CFDictionaryRef ident = CFArrayGetValueAtIndex(items,0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue(ident, kSecImportItemIdentity);
        *identity = (SecIdentityRef)tempIdentity;
    }
    else
    {
        NetLog(@"clinet.p12 error!");
    }
    
    if (options) {
        CFRelease(options);
    }
    return securityError;
}
#pragma mark - 内部方法

//static inline NSString * AFContentTypeForPathExtension(NSString *extension) {
//#ifdef __UTTYPE__
//    NSString *UTI = (__bridge_transfer NSString *)UTTypeCreatePreferredIdentifierForTag(kUTTagClassFilenameExtension, (__bridge CFStringRef)extension, NULL);
//    NSString *contentType = (__bridge_transfer NSString *)UTTypeCopyPreferredTagWithClass((__bridge CFStringRef)UTI, kUTTagClassMIMEType);
//    if (!contentType) {
//        return @"application/octet-stream";
//    } else {
//        return contentType;
//    }
//#else
//#pragma unused (extension)
//    return @"application/octet-stream";
//#endif
//}

#pragma mark NSMutableData

/**
 生成上传文件数据

 @param fpathArray 文件详情 @[@{@"fileName":@"",@"contentType":@"",@"data":nsdata}]
 @param boundary 加密码
 @return 数据
 */
-(NSMutableData *)createFileMutableDataWithFile:(NSArray*)fpathArray Boundary:(NSString*)boundary
{
    //拼接请求体数据(1-6步)
    NSMutableData *requestMutableData=[NSMutableData data];
     for (int i = 0;i<fpathArray.count;i++) {
         NSDictionary* fpath = [fpathArray objectAtIndex:i];
         NSString* fileName = [fpath objectForKey:@"fileName"];
         NSData* oneFileData = [fpath objectForKey:@"data"];
         
         /*--------------------------------------------------------------------------*/
         //1.\r\n--Boundary+72D4CD655314C423\r\n   // 分割符，以“--”开头，后面的字随便写，只要不写中文即可
         NSMutableString *myString = [[NSMutableString alloc] init];
         if (i==0) {
             /*--------------------------------------------------------------------------*/
             //1.\r\n--Boundary+72D4CD655314C423\r\n   // 分割符，以“--”开头，后面的字随便写，只要不写中文即可
             myString=[NSMutableString stringWithFormat:@"--%@\r\n",boundary];
             //转换成为二进制数据
             
         }
         
         NSString *contentType = [fpath objectForKey:@"contentType"];//AFContentTypeForPathExtension([fpath pathExtension]);
         if (contentType==nil||contentType.length==0) {
             contentType = @"application/octet-stream";
         }
         
         [myString appendString:[NSString stringWithFormat:@"Content-Disposition: form-data; name=\"%@\"; filename=\"%@\";Content-type=%@\r\n\r\n",@"file",fileName,contentType]];
         
         //转换成为二进制数据
         [requestMutableData appendData:[myString dataUsingEncoding:NSUTF8StringEncoding]];
         
         //5.文件数据部分
         NSData* fileData = [NSData dataWithData:oneFileData];
         
         //转换成为二进制数据
         [requestMutableData appendData:fileData];
         
     
         if (i<fpathArray.count-1) {
             //6. \r\n--Boundary+72D4CD655314C423\r\n  // 分隔符后面以"--"结尾，表明结束
             [requestMutableData appendData:[[NSString stringWithFormat:@"\r\n--%@\r\n",boundary] dataUsingEncoding:NSUTF8StringEncoding]];
         }
         else
         {
             //6. \r\n--Boundary+72D4CD655314C423--\r\n  // 分隔符后面以"--"结尾，表明结束
             [requestMutableData appendData:[[NSString stringWithFormat:@"\r\n--%@--\r\n",boundary] dataUsingEncoding:NSUTF8StringEncoding]];
         }
         
     }
    
    
    return requestMutableData;
}
-(NSMutableData *)createPostMutableDataTypeWithParamter:(NSDictionary*)paramDic Boundary:(NSString*)boundary
{
    //拼接请求体数据(1-6步)
    NSMutableData *requestMutableData=[NSMutableData data];
    for (int i = 0;i<paramDic.count;i++) {
        NSString* key = [[paramDic allKeys] objectAtIndex:i];
        NSMutableString *myString = [[NSMutableString alloc] init];
        if (i==0) {
            /*--------------------------------------------------------------------------*/
            //1.\r\n--Boundary+72D4CD655314C423\r\n   // 分割符，以“--”开头，后面的字随便写，只要不写中文即可
            myString=[NSMutableString stringWithFormat:@"--%@\r\n",boundary];
            //转换成为二进制数据
            
        }
        
        
        NSDictionary* valueDic = [paramDic objectForKey:key];
        NSString* contentType = [valueDic valueForKey:@"contentType"];
        NSString* value = [valueDic valueForKey:@"value"];
        
        //header部分
        if ([key isEqualToString:@"file"]) {
            NSString* filename = [valueDic valueForKey:@"fileName"];
            [myString appendString:[NSString stringWithFormat:@"Content-Disposition: form-data; name=\"%@\";filename=\"%@\"\r\nContent-type=%@\r\nContent-Length:%lu\r\n\r\n%@",key,filename,contentType,(unsigned long)value.length,value]];
        }
        else
        {
            [myString appendString:[NSString stringWithFormat:@"Content-Disposition: form-data; name=\"%@\"\r\nContent-Transfer-Encoding: 8bit\r\nContent-type=%@\r\nContent-Length:%lu\r\n\r\n%@",key,contentType,(unsigned long)value.length,value]];
        }
        
        [requestMutableData appendData:[myString dataUsingEncoding:NSUTF8StringEncoding]];
//        //5.文件数据部分
//        NSData* fileData = [value dataUsingEncoding:NSUTF8StringEncoding];
//
//        //转换成为二进制数据
//        [requestMutableData appendData:fileData];
        
        if (i<paramDic.count-1) {
            //6. \r\n--Boundary+72D4CD655314C423--\r\n  // 分隔符后面以"--"结尾，表明结束
            [requestMutableData appendData:[[NSString stringWithFormat:@"\r\n--%@\r\n",boundary] dataUsingEncoding:NSUTF8StringEncoding]];
        }
        else
        {
            //6. \r\n--Boundary+72D4CD655314C423--\r\n  // 分隔符后面以"--"结尾，表明结束
            [requestMutableData appendData:[[NSString stringWithFormat:@"\r\n--%@--\r\n",boundary] dataUsingEncoding:NSUTF8StringEncoding]];
        }
    }
    
    return requestMutableData;
}
-(NSMutableData *)createPostMutableDataWithParamter:(NSDictionary*)paramDic Boundary:(NSString*)boundary
{
    //拼接请求体数据(1-6步)
    NSMutableData *requestMutableData=[NSMutableData data];
    for (int i = 0;i<paramDic.count;i++) {
        NSString* key = [[paramDic allKeys] objectAtIndex:i];
        NSMutableString *myString = [[NSMutableString alloc] init];
        if (i==0) {
            /*--------------------------------------------------------------------------*/
            //1.\r\n--Boundary+72D4CD655314C423\r\n   // 分割符，以“--”开头，后面的字随便写，只要不写中文即可
            myString=[NSMutableString stringWithFormat:@"--%@\r\n",boundary];
            //转换成为二进制数据
            
        }
        [myString appendString:[NSString stringWithFormat:@"Content-Disposition: form-data; name=\"%@\"\r\n\r\n",key]];
        [requestMutableData appendData:[myString dataUsingEncoding:NSUTF8StringEncoding]];
        //5.文件数据部分
        NSData* fileData = [[paramDic objectForKey:key] dataUsingEncoding:NSUTF8StringEncoding];
        
        //转换成为二进制数据
        [requestMutableData appendData:fileData];
        
        if (i<paramDic.count-1) {
            //6. \r\n--Boundary+72D4CD655314C423--\r\n  // 分隔符后面以"--"结尾，表明结束
            [requestMutableData appendData:[[NSString stringWithFormat:@"\r\n--%@\r\n",boundary] dataUsingEncoding:NSUTF8StringEncoding]];
        }
        else
        {
            //6. \r\n--Boundary+72D4CD655314C423--\r\n  // 分隔符后面以"--"结尾，表明结束
            [requestMutableData appendData:[[NSString stringWithFormat:@"\r\n--%@--\r\n",boundary] dataUsingEncoding:NSUTF8StringEncoding]];
        }
    }
    
    return requestMutableData;
}
#pragma mark request
-(NSMutableDictionary*)getHeaderBy:(NSDictionary*)header
{
    NSMutableDictionary* requestHeader = [[NSMutableDictionary alloc] init];
    if (self.publicHeader) {
        NSArray* allkeys = [self.publicHeader allKeys];
        for (NSString* key in allkeys) {
            [requestHeader setObject:[self.publicHeader objectForKey:key] forKey:key];
        }
    }
    if (header) {
        NSArray* allkeys = [header allKeys];
        for (NSString* key in allkeys) {
            [requestHeader setObject:[header objectForKey:key] forKey:key];
        }
    }
    return requestHeader;
}
-(NSMutableURLRequest *)createRequestWithMethod:(NSString*)method Url:(NSString*)urlStr header:(NSDictionary *)headerDic parameters:(NSDictionary *)paramDic
{
    NSURL *url = [NSURL URLWithString:urlStr];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestUseProtocolCachePolicy timeoutInterval:RequestTimeoutInterval];
    
    //设置方法
    request.HTTPMethod = method;//设置请求方法是POST

    //设置消息体
    if (paramDic != nil) {
        request.HTTPBody = [NSJSONSerialization dataWithJSONObject:paramDic options:NSJSONWritingPrettyPrinted error:nil];
    }
    
    //设置header
    NSMutableDictionary* header = [self getHeaderBy:headerDic];
    if ([header objectForKey:ContentTypeKey]==nil) {
        [header setObject:ContentType_ApplicationJson forKey:ContentTypeKey];
    }
    
    [SCNetworking setHttpHeader:header inRequest:request];

    return request;
}

+(void)setHttpHeader:(NSDictionary*)headerDic inRequest:(NSMutableURLRequest *)request
{
    //设置header
    @synchronized (self) {
        NSMutableDictionary* header = [NSMutableDictionary dictionaryWithDictionary:headerDic];
        if ([header objectForKey:@"sign"] == nil) {
            //md5签名
            NSString*signMD5 = [SCNetworking getSignFrom:headerDic HttpBody:request.HTTPBody];
            [header setObject:signMD5 forKey:@"sign"];
        }
        
        [request setAllHTTPHeaderFields:header];
    }
}
+(void)setHttpBody:(NSData*)data inRequest:(NSMutableURLRequest*)request
{
    request.HTTPBody = data;
    [SCNetworking setHttpHeader:request.allHTTPHeaderFields inRequest:request];
}

#pragma mark datatask
//创建NSURLSessionDataTask
-(NSURLSessionDataTask*)createJsonDataTaskWith:(NSMutableURLRequest *)request completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
{
    [self.requestTimeDic setObject:[NSDate date] forKey:request];
    
    NSURLSession *session = [[SCNetworking shareInstance] customSession];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request
                                            completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error)
                                  {
                                      //解析数据
                                      NSHTTPURLResponse* httpResponse = (NSHTTPURLResponse*)response;
                                      NSDictionary* responseDic;
                                      
                                      BOOL isSuccess = NO;
                                      if (error==nil) {
                                          if (data!=nil&&data.length>0) {
                                              isSuccess = YES;
                                              responseDic = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableLeaves error:&error];
                                              if (error) {
                                                  responseDic = nil;
                                              }
                                          }
                                          else if(httpResponse.statusCode==200)
                                          {
                                              isSuccess = YES;
                                          }
                                      }
                                      
                                      //log
                                      [[SCNetworking shareInstance] printResponse:response request:request withData:responseDic withError:error];
                                      
                                      if (isSuccess) {
                                          dispatch_async(dispatch_get_main_queue(), ^{
                                              success ? success(response, responseDic) : nil;
                                          });
                                      }
                                      else
                                      {
                                          if (error==nil) {
                                              error = [self errorWithHTTPURLResponse:httpResponse];
                                          }
                                          
                                          
                                          dispatch_async(dispatch_get_main_queue(), ^{
                                              failed ? failed(response,error) : nil;
                                          });
                                      }
                                  }];
    
    return task;
}


-(NSURLSessionDataTask*)createRawDataTaskWith:(NSMutableURLRequest *)request completionSuccess:(void (^)(NSURLResponse *response, NSData *data))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
{
    NSURLSession *session = [[SCNetworking shareInstance] customSession];
    
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request
                                            completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error)
                                  {
                                      
                                      NSHTTPURLResponse* httpResponse = (NSHTTPURLResponse*)response;
                                      BOOL isSuccess = NO;
                                      if (error==nil) {
                                          if (data!=nil&&data.length>0) {
                                              isSuccess = YES;
                                          }
                                          else if (httpResponse.statusCode==200)
                                          {
                                              isSuccess = YES;
                                          }
                                      }
                                      if (isSuccess) {
                                          dispatch_async(dispatch_get_main_queue(), ^{
                                              success ? success(response, data) : nil;
                                          });
                                      }
                                      else
                                      {
                                          if (error==nil) {
                                              error = [self errorWithHTTPURLResponse:httpResponse];
                                          }
                                          dispatch_async(dispatch_get_main_queue(), ^{
                                              failed ? failed(response,error) : nil;
                                          });
                                      }
                                      
                                  }];
    
    return task;
}
-(NSURLSessionUploadTask*)createUploadTaskWith:(NSMutableURLRequest *)request Data:(NSMutableData *)requestMutableData completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
{
    [self.requestTimeDic setObject:[NSDate date] forKey:request];
    
    NSURLSessionUploadTask*dataTask = [[[SCNetworking shareInstance] customSession] uploadTaskWithRequest:request fromData:requestMutableData completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {

        
        //解析数据
        NSHTTPURLResponse* httpResponse = (NSHTTPURLResponse*)response;
        NSDictionary* responseDic;
        BOOL isSuccess = NO;
        if (error==nil) {
            if (data!=nil&&data.length>0) {
                isSuccess = YES;
                responseDic = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableLeaves error:&error];
                if (error) {
                    responseDic = @{@"data":data};
                }
            }
            else if (httpResponse.statusCode==200)
            {
                isSuccess = YES;
            }
        }
        
        //log
        [[SCNetworking shareInstance] printResponse:response request:request withData:responseDic withError:error];
        
        if (isSuccess) {
            
            dispatch_async(dispatch_get_main_queue(), ^{
                success ? success(response, responseDic) : nil;
            });
        }
        else
        {
            if (error==nil) {
                error = [self errorWithHTTPURLResponse:httpResponse];
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                failed ? failed(response,error) : nil;
            });
        }
    }];
    return dataTask;
}

#pragma mark HTTP错误码处理
-(NSError*)errorWithHTTPURLResponse:(NSHTTPURLResponse*)response
{
    NSError* error=nil;
    if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
        NSString* errorMsg = [NSHTTPURLResponse localizedStringForStatusCode:response.statusCode];
        error = [NSError errorWithDomain:@"NSHTTPURLResponse" code:response.statusCode userInfo:@{NSLocalizedDescriptionKey:errorMsg}];
    }
    
    return error;
}
#pragma mark - 配置
/**
 配置公共header
 
 @param header 请求头
 */
+(void)setPublicHeader:(NSDictionary*)header
{
    [[SCNetworking shareInstance] setPublicHeader:header];
}
/**
 配置HTTPS自有证书
 
 @param caPath 证书路径
 */
+(void)configHTTPSCertificateWith:(NSString*)caPath
{
    [[SCNetworking shareInstance] setCaData:[NSData dataWithContentsOfFile:caPath]];
}

/**
 设置客户端证书
 
 @param clientPath 证书路径
 */
+(void)configHTTPSClientCertificateWith:(NSString*)clientPath  Password:(NSString*)pw
{
    [[SCNetworking shareInstance] setClientData:[NSData dataWithContentsOfFile:clientPath]];
    [[SCNetworking shareInstance] setClientPassword:pw];
}



#pragma mark - 请求方法
#pragma mark base
//-(NSURLSessionDataTask*)requestWithMethod:(NSString*)method header:(NSDictionary *)headerDic parameters:(NSDictionary *)paramDic filePath:(NSArray*)fpaths completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
//{
//    if ([[method uppercaseString] isEqualToString:@"upload"]) {
//        
//    }
//}
#pragma mark upload

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
+(NSURLSessionUploadTask*)upload:(NSString*)urlStr header:(NSDictionary *)headerDic parameters:(NSDictionary *)paramDic fileDetail:(NSArray*)fpaths completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
{
    NSMutableURLRequest *request = [[SCNetworking shareInstance] createRequestWithMethod:@"POST" Url:urlStr header:headerDic parameters:paramDic];
    
    request.timeoutInterval = 600;//暂定10分钟

    //设置请求头
    NSString *boundary=@"fetceakdzdjiogtngakdfajoi99875-jk";

    NSString *headStr=[NSString stringWithFormat:@"multipart/form-data; boundary=%@",boundary];
    [request setValue:headStr forHTTPHeaderField:ContentTypeKey];
    
    NSMutableData *requestMutableData=[[SCNetworking shareInstance] createFileMutableDataWithFile:fpaths Boundary:boundary];
    
    [request setValue:[NSString stringWithFormat:@"%lu",(unsigned long)requestMutableData.length] forHTTPHeaderField:@"Content-Length"];
    
    //log
    [[SCNetworking shareInstance] printRequest:request withHeader:request.allHTTPHeaderFields withParamter:paramDic];
    
    NSURLSessionUploadTask*dataTask = [[SCNetworking shareInstance] createUploadTaskWith:request Data:requestMutableData completionSuccess:success failed:failed];
    dataTask.taskDescription = [NSString stringWithFormat:@"%lu",(unsigned long)fpaths.count];
    [dataTask resume];
    return dataTask;
}

#pragma mark post
+(NSURLSessionDataTask *)post:(NSString*)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary*)paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
{

    NSMutableURLRequest *request = [[SCNetworking shareInstance] createRequestWithMethod:@"POST" Url:urlStr header:headerDic parameters:paramDic];
    
    //log
    [[SCNetworking shareInstance] printRequest:request withHeader:request.allHTTPHeaderFields withParamter:paramDic];
    NSURLSessionDataTask *task = [[SCNetworking shareInstance] createJsonDataTaskWith:request completionSuccess:success failed:failed];
    [task resume];
    
    return task;
}
+(NSURLSessionDataTask *)post:(SCBatchRequestConfigBlock)batchBlock completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
{
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] init];
    [request setValue:ContentType_ApplicationJson forHTTPHeaderField:ContentTypeKey];
    request.timeoutInterval = RequestTimeoutInterval;
    request.HTTPMethod = @"POST";
    SC_SAFE_BLOCK(batchBlock,request);
    
    
    NSURLSessionDataTask *task = [[SCNetworking shareInstance] createJsonDataTaskWith:request completionSuccess:success failed:failed];
    [task resume];
    return task;
}
+(NSURLSessionDataTask *)postWithFormEncode:(NSString*)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary*)paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed

{
    
    NSString* trailStr = urlStr;
    if (paramDic) {
        for (int i = 0; i<paramDic.allKeys.count; i++) {
            NSString*key = [paramDic.allKeys objectAtIndex:i];
            NSString* value = [paramDic objectForKey:key];
            if (i==0) {
                trailStr = [NSString stringWithFormat:@"%@?%@=%@",trailStr,key,value];
            }
            else
            {
                trailStr = [NSString stringWithFormat:@"%@&%@=%@",trailStr,key,value];
            }
        }
    }
    
    trailStr = [trailStr stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    NSURL *url = [NSURL URLWithString:trailStr];
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url cachePolicy:NSURLRequestUseProtocolCachePolicy timeoutInterval:RequestTimeoutInterval];

    request.HTTPMethod = @"POST";
    
    //设置header
    NSMutableDictionary* header = [[SCNetworking shareInstance] getHeaderBy:headerDic];
    [header setObject:@"application/x-www-form-urlencoded;charset=utf-8;" forKey:ContentTypeKey];
    [SCNetworking setHttpHeader:header inRequest:request];
    
    //log
    [[SCNetworking shareInstance] printRequest:request withHeader:request.allHTTPHeaderFields withParamter:paramDic];
    
    NSURLSessionDataTask *task = [[SCNetworking shareInstance] createJsonDataTaskWith:request completionSuccess:success failed:failed];
    [task resume];
    return task;
}
+(NSURLSessionDataTask *)postOfFormdata:(NSString*)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary*)paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed

{
    //设置请求头
    NSMutableDictionary* headerCopy = [NSMutableDictionary dictionaryWithDictionary:headerDic];

    NSString *boundary=@"769827829257045108633989!sc";
    NSString *headStr=[NSString stringWithFormat:@"multipart/form-data; boundary=%@",boundary];
    
    [headerCopy setValue:headStr forKey:ContentTypeKey];
    NSMutableURLRequest *request = [[SCNetworking shareInstance] createRequestWithMethod:@"POST" Url:urlStr header:headerCopy parameters:paramDic];

    
    NSMutableData* requestMutableData = [[SCNetworking shareInstance] createPostMutableDataWithParamter:paramDic Boundary:boundary];
    
    [request setValue:[NSString stringWithFormat:@"%lu",(unsigned long)requestMutableData.length] forHTTPHeaderField:@"Content-Length"];
    
    [SCNetworking setHttpBody:requestMutableData inRequest:request];
    
    //log
    [[SCNetworking shareInstance] printRequest:request withHeader:request.allHTTPHeaderFields withParamter:paramDic];
    
    NSURLSessionDataTask *task = [[SCNetworking shareInstance] createJsonDataTaskWith:request completionSuccess:success failed:failed];
    [task resume];
    return task;
}

+(NSURLSessionDataTask *)postFormdataWithMutableType:(NSString*)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary*)paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed

{
    //设置请求头
    NSMutableDictionary* headerCopy = [NSMutableDictionary dictionaryWithDictionary:headerDic];

    NSString *boundary=@"769827829257045108633989!sc";
    NSString *headStr=[NSString stringWithFormat:@"multipart/form-data; boundary=%@",boundary];
    [headerCopy setValue:headStr forKey:ContentTypeKey];
    NSMutableURLRequest *request = [[SCNetworking shareInstance] createRequestWithMethod:@"POST" Url:urlStr header:headerCopy parameters:paramDic];
    
    NSMutableData* requestMutableData = [[SCNetworking shareInstance] createPostMutableDataTypeWithParamter:paramDic Boundary:boundary];
    
    [request setValue:[NSString stringWithFormat:@"%lu",(unsigned long)requestMutableData.length] forHTTPHeaderField:@"Content-Length"];
    
    [SCNetworking setHttpBody:requestMutableData inRequest:request];
    
    //log
    [[SCNetworking shareInstance] printRequest:request withHeader:request.allHTTPHeaderFields withParamter:paramDic];
    
    NSURLSessionDataTask *task = [[SCNetworking shareInstance] createJsonDataTaskWith:request completionSuccess:success failed:failed];
    [task resume];
    return task;
}
#pragma mark get
+(NSURLSessionDataTask *)get:(NSString *)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary* )paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
{
    //url处理
    NSString*getURLStr = urlStr;
    if (paramDic != nil&& paramDic.count>0) {
        getURLStr = [NSString stringWithFormat:@"%@?",getURLStr];
        NSArray* allKeys = [paramDic allKeys];
        for (int i = 0;i<allKeys.count;i++) {
            NSString*key = [allKeys objectAtIndex:i];
            if (i==0) {
                getURLStr = [NSString stringWithFormat:@"%@%@=%@",getURLStr,key,[paramDic objectForKey:key]];
            }
            else
            {
                getURLStr = [NSString stringWithFormat:@"%@&%@=%@",getURLStr,key,[paramDic objectForKey:key]];
            }
            
        }
    }
    getURLStr = [getURLStr stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet characterSetWithCharactersInString:@"`#%^{}\"[]|\\<> "].invertedSet];
 
    
    NSMutableURLRequest *request = [[SCNetworking shareInstance] createRequestWithMethod:@"GET" Url:getURLStr header:headerDic parameters:nil];

    //log
    [[SCNetworking shareInstance] printRequest:request withHeader:request.allHTTPHeaderFields withParamter:paramDic];
    
    //请求
    NSURLSessionDataTask *task = [[SCNetworking shareInstance] createJsonDataTaskWith:request completionSuccess:success failed:failed];
    [task resume];
    return task;
}
+(NSURLSessionDataTask *)get:(SCBatchRequestConfigBlock)batchBlock completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
{
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] init];
    request.timeoutInterval = RequestTimeoutInterval;
    request.HTTPMethod = @"GET";
    SC_SAFE_BLOCK(batchBlock,request);
    
    //请求
    NSURLSessionDataTask *task = [[SCNetworking shareInstance] createJsonDataTaskWith:request completionSuccess:success failed:failed];
    [task resume];
    return task;
}
+(NSURLSessionDataTask *)getRawDataFrom:(NSString *)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary* )paramDic completionSuccess:(void (^)(NSURLResponse *response, NSData *data))success failed:(void (^)(NSURLResponse *response,NSError *error))failed;
{
    //url处理
    NSString*getURLStr = urlStr;
    if (paramDic != nil&& paramDic.count > 0) {
        getURLStr = [NSString stringWithFormat:@"%@?",getURLStr];
        NSArray* allKeys = [paramDic allKeys];
        for (int i = 0;i<allKeys.count;i++) {
            NSString*key = [allKeys objectAtIndex:i];
            if (i==0) {
                getURLStr = [NSString stringWithFormat:@"%@%@=%@",getURLStr,key,[paramDic objectForKey:key]];
            }
            else
            {
                getURLStr = [NSString stringWithFormat:@"%@&%@=%@",getURLStr,key,[paramDic objectForKey:key]];
            }
            
        }
    }
    getURLStr = [getURLStr stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet characterSetWithCharactersInString:@"`#%^{}\"[]|\\<> "].invertedSet];
    
    
    NSMutableURLRequest *request = [[SCNetworking shareInstance] createRequestWithMethod:@"GET" Url:getURLStr header:headerDic parameters:nil];
    
    //log
    [[SCNetworking shareInstance] printRequest:request withHeader:request.allHTTPHeaderFields withParamter:paramDic];
    
    //请求
    NSURLSessionDataTask *task = [[SCNetworking shareInstance] createRawDataTaskWith:request completionSuccess:success failed:failed];
    
    [task resume];
    return task;
}
#pragma mark put
+(NSURLSessionDataTask *)put:(NSString *)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary* )paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
{
    NSMutableURLRequest *request = [[SCNetworking shareInstance] createRequestWithMethod:@"PUT" Url:urlStr header:headerDic parameters:paramDic];
    
    //log
    [[SCNetworking shareInstance] printRequest:request withHeader:request.allHTTPHeaderFields withParamter:paramDic];
    
    //请求
    NSURLSessionDataTask *task = [[SCNetworking shareInstance] createJsonDataTaskWith:request completionSuccess:success failed:failed];

    [task resume];
    return task;
}
+(NSURLSessionDataTask *)put:(SCBatchRequestConfigBlock)batchBlock completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
{
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] init];
    request.timeoutInterval = RequestTimeoutInterval;
    request.HTTPMethod = @"PUT";
    SC_SAFE_BLOCK(batchBlock,request);
    
    //请求
    NSURLSessionDataTask *task = [[SCNetworking shareInstance] createJsonDataTaskWith:request completionSuccess:success failed:failed];

    [task resume];
    return task;
}

-(NSMutableData *)createFileMutableDataWithData:(NSData*)oneFileData ContentType:(NSString*)contentType FileName:(NSString*)fileName Boundary:(NSString*)boundary
{
    //拼接请求体数据(1-6步)
    NSMutableData *requestMutableData=[NSMutableData data];
         
     /*--------------------------------------------------------------------------*/
     //1.\r\n--Boundary+72D4CD655314C423\r\n   // 分割符，以“--”开头，后面的字随便写，只要不写中文即可
     NSMutableString *myString =[NSMutableString stringWithFormat:@"--%@\r\n",boundary];
     //转换成为二进制数据
     if (contentType==nil||contentType.length==0) {
         contentType = @"application/octet-stream";
     }
     
     [myString appendString:[NSString stringWithFormat:@"Content-Disposition: form-data; name=\"%@\"; filename=\"%@\";Content-type=%@\r\n\r\n",@"file",fileName,contentType]];
     
     //转换成为二进制数据
     [requestMutableData appendData:[myString dataUsingEncoding:NSUTF8StringEncoding]];
     
     //5.数据
     [requestMutableData appendData:oneFileData];
     
 
     //6. \r\n--Boundary+72D4CD655314C423--\r\n  // 分隔符后面以"--"结尾，表明结束
     [requestMutableData appendData:[[NSString stringWithFormat:@"\r\n--%@--\r\n",boundary] dataUsingEncoding:NSUTF8StringEncoding]];
    
    return requestMutableData;
}
/**
 上传文件

 @param urlStr 网址
 @param headerDic header
 @param paramDic 参数
 @param success 成功返回
 @param failed 失败返回
 @return 任务对象
 */
+(NSURLSessionUploadTask*)uploadPutWith:(NSString*)urlStr header:(NSDictionary *)headerDic parameters:(NSDictionary *)paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
{
    NSMutableURLRequest *request = [[SCNetworking shareInstance] createRequestWithMethod:@"PUT" Url:urlStr header:headerDic parameters:nil];
    
    request.timeoutInterval = 600;//暂定10分钟

    //设置请求头
    NSString *boundary=@"fetceakdzdjiogtngakdfajoi99875ddsjk";

    NSString *headStr=[NSString stringWithFormat:@"multipart/form-data; boundary=%@",boundary];
    [request setValue:headStr forHTTPHeaderField:ContentTypeKey];
    
    NSMutableData *requestMutableData=[[SCNetworking shareInstance] createFileMutableDataWithData:[paramDic objectForKey:@"file"] ContentType:@"multipart/form-data" FileName:@"filename" Boundary:boundary];
    
    [request setValue:[NSString stringWithFormat:@"%lu",(unsigned long)requestMutableData.length] forHTTPHeaderField:@"Content-Length"];
    NSLog(@"[SCNetworking] %@",[[NSString alloc] initWithData:requestMutableData encoding:NSUTF8StringEncoding]);
    //log
    [[SCNetworking shareInstance] printRequest:request withHeader:request.allHTTPHeaderFields withParamter:paramDic];
    
    NSURLSessionUploadTask*dataTask = [[SCNetworking shareInstance] createUploadTaskWith:request Data:requestMutableData completionSuccess:success failed:failed];
    dataTask.taskDescription = [paramDic objectForKey:@"desc"]?:@"";
    [dataTask resume];
    return dataTask;
}
#pragma mark patch
+(NSURLSessionDataTask *)patch:(NSString *)urlStr header:(NSDictionary * )headerDic parameters:(NSDictionary* )paramDic completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
{
    NSMutableURLRequest *request = [[SCNetworking shareInstance] createRequestWithMethod:@"PATCH" Url:urlStr header:headerDic parameters:paramDic];
    
    //log
    [[SCNetworking shareInstance] printRequest:request withHeader:request.allHTTPHeaderFields withParamter:paramDic];
    
    //请求
    NSURLSessionDataTask *task = [[SCNetworking shareInstance] createJsonDataTaskWith:request completionSuccess:success failed:failed];

    [task resume];
    return task;
}
+(NSURLSessionDataTask *)patch:(SCBatchRequestConfigBlock)batchBlock completionSuccess:(void (^)(NSURLResponse *response, NSDictionary *responseDictionary))success failed:(void (^)(NSURLResponse *response,NSError *error))failed
{
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] init];
    request.timeoutInterval = RequestTimeoutInterval;
    request.HTTPMethod = @"patch";
    SC_SAFE_BLOCK(batchBlock,request);
    
    
    //请求
    NSURLSessionDataTask *task = [[SCNetworking shareInstance] createJsonDataTaskWith:request completionSuccess:success failed:failed];

    [task resume];
    return task;
}

@end
