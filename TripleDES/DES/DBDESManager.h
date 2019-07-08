//
//  DBDESManager.h
//  TripleDES
//
//  Created by 徐结兵 on 2019/7/8.
//  Copyright © 2019 徐结兵. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum : NSUInteger {
    DBDESEncrypt,
    DBDESDecrypt,
} DBDESType;

NS_ASSUME_NONNULL_BEGIN

@interface DBDESManager : NSObject

/**
 DES加密
 
 @param string 明文
 @param secretKey 密钥
 @return 密文
 */
+ (NSString *)encryptString:(NSString *)string
                  secretKey:(NSString *)secretKey;

/**
 DES解密
 
 @param string 密文
 @param secretKey 密钥
 @return 明文
 */
+ (NSString *)decryptString:(NSString *)string
                  secretKey:(NSString *)secretKey;

/**
 3DES加解密
 
 @param string 待 加密/解密 字符串
 @param secretKey 密钥
 @param type 类型 加密/解密
 @return 加密/解密 之后的字符串
 */
+ (NSString *)triplrDESWithString:(NSString *)string
                        secretKey:(NSString *)secretKey
                             type:(DBDESType)type;

@end

NS_ASSUME_NONNULL_END
