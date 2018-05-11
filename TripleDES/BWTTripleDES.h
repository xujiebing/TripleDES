//
//  BWTTripleDES.h
//  TripleDES
//
//  Created by 徐结兵 on 2018/5/11.
//  Copyright © 2018年 八维通. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface BWTTripleDES : NSObject

/**
 字符串加密

 @param string 待加密字符串
 @return 加密之后的密文
 */
+ (NSString *)encryptString:(NSString *)string;

/**
 字符串解密

 @param encryptString 待解密字符串
 @return 解密之后的明文
 */
+ (NSString *)decryptString:(NSString *)encryptString;

/**
 十六进制加密

 @param hexString 待加密十六进制字符串
 @return 加密之后的密文
 */
+ (NSString *)encryptHexString:(NSString *)hexString;

/**
 十六进制解密

 @param encryptHexString 待解密十六进制字符串
 @return 解密之后的明文
 */
+ (NSString *)decryptHexString:(NSString *)encryptHexString;

@end
