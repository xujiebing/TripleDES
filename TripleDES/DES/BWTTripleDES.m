//
//  BWTTripleDES.m
//  TripleDES
//
//  Created by 徐结兵 on 2018/5/11.
//  Copyright © 2018年 徐结兵. All rights reserved.
//

#import "BWTTripleDES.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>
#import "NSData+BWTBase64.h"

static NSString *kBWTTripleDESKey = @"bwton"; // 加密的秘钥
static NSString *kBWTTripleDESOffset = @"iOS"; // 偏移量

@implementation BWTTripleDES

+ (NSString *)encryptString:(NSString *)string {
    // 把string转NSData
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    // length
    size_t plainTextBufferSize = [data length];
    const void *vplainText = (const void *)[data bytes];
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    const void *vkey = (const void *) [kBWTTripleDESKey UTF8String];
    // 偏移量，不用的话必须设置成nil，不能设置成其他任何形式
    const void *vinitVec = (const void *) [kBWTTripleDESOffset UTF8String];
    
    // 配置 CCCrypt
    ccStatus = CCCrypt(kCCEncrypt,
                       kCCAlgorithm3DES,
                       kCCOptionECBMode|kCCOptionPKCS7Padding, // 设置模式,这个设置跟安卓不一样
                       vkey,
                       kCCKeySize3DES,
                       vinitVec,
                       vplainText,
                       plainTextBufferSize,
                       (void *)bufferPtr,
                       bufferPtrSize,
                       &movedBytes);
    
    NSData *myData = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes];
    NSString *result = [myData base64EncodedString];
    return result;
}

+ (NSString *)decryptString:(NSString *)encryptString {
    NSData *encryptData = [NSData dataFromBase64String:encryptString];
    size_t plainTextBufferSize = [encryptData length];
    const void *vplainText = [encryptData bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    const void *vkey = (const void *) [kBWTTripleDESKey UTF8String];
    const void *vinitVec = (const void *) [kBWTTripleDESOffset UTF8String];
    
    ccStatus = CCCrypt(kCCDecrypt,
                       kCCAlgorithm3DES,
                       kCCOptionPKCS7Padding|kCCOptionECBMode,
                       vkey,
                       kCCKeySize3DES,
                       vinitVec,
                       vplainText,
                       plainTextBufferSize,
                       (void *)bufferPtr,
                       bufferPtrSize,
                       &movedBytes);
    
    NSData *resultData = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes];
    NSString *result = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    return result;
}

+ (NSString *)encryptHexString:(NSString *)hexString {
    // 把string 转NSData
    NSData *data = [hexString dataUsingEncoding:NSUTF8StringEncoding];
    // length
    size_t plainTextBufferSize = [data length];
    const void *vplainText = (const void *)[data bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    const void *vkey = (const void *) [kBWTTripleDESKey UTF8String];
    // 偏移量，不用的话必须设置成nil，不能设置成其他任何形式
    const void *vinitVec = (const void *) [kBWTTripleDESOffset UTF8String];

    // 配置CCCrypt
    ccStatus = CCCrypt(kCCEncrypt,
                       kCCAlgorithm3DES,
                       kCCOptionECBMode|kCCOptionPKCS7Padding, // 设置模式,这个设置跟安卓不一样
                       vkey,
                       kCCKeySize3DES,
                       vinitVec,
                       vplainText,
                       plainTextBufferSize,
                       (void *)bufferPtr,
                       bufferPtrSize,
                       &movedBytes);
    
    NSData *myData = [NSData dataWithBytes:(const char *)bufferPtr length:(NSUInteger)movedBytes];
    
    NSUInteger len = [myData length];
    char * chars = (char *)[myData bytes];
    NSMutableString *resultString = [[NSMutableString alloc] init];
    for(NSUInteger i = 0; i < len; i++ ) {
        [resultString appendString:[NSString stringWithFormat:@"%0.2hhx", chars[i]]];
    }
    
    return resultString;
    
}

+ (NSString *)decryptHexString:(NSString *)encryptHexString {
    //十六进制转NSData
    long len = [encryptHexString length] / 2;
    unsigned char *buf = malloc(len);
    unsigned char *whole_byte = buf;
    char byte_chars[3] = {'\0','\0','\0'};
    
    int i;
    for (i=0; i < [encryptHexString length] / 2; i++) {
        byte_chars[0] = [encryptHexString characterAtIndex:i*2];
        byte_chars[1] = [encryptHexString characterAtIndex:i*2+1];
        *whole_byte = strtol(byte_chars, NULL, 16);
        whole_byte++;
    }
    
    NSData *encryptData = [NSData dataWithBytes:buf length:len];
    
    size_t plainTextBufferSize = [encryptData length];
    const void *vplainText = [encryptData bytes];
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    const void *vkey = (const void *) [kBWTTripleDESKey UTF8String];
    const void *vinitVec = (const void *) [kBWTTripleDESOffset UTF8String];
    
    ccStatus = CCCrypt(kCCDecrypt,
                       kCCAlgorithm3DES,
                       kCCOptionPKCS7Padding|kCCOptionECBMode,
                       vkey,
                       kCCKeySize3DES,
                       vinitVec,
                       vplainText,
                       plainTextBufferSize,
                       (void *)bufferPtr,
                       bufferPtrSize,
                       &movedBytes);
    
    NSData *resultData = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes];
    NSString *result = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];    
    return result;
}


@end
