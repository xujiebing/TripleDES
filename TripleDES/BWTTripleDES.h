//
//  BWTTripleDES.h
//  TripleDES
//
//  Created by 徐结兵 on 2018/5/11.
//  Copyright © 2018年 八维通. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface BWTTripleDES : NSObject

/**字符串加密 */
+ (NSString *)doEncryptStr:(NSString *)originalStr;
/**字符串解密 */
+ (NSString*)doDecEncryptStr:(NSString *)encryptStr;
/**十六进制解密 */
-(NSString *)doEncryptHex:(NSString *)originalStr;
/**十六进制加密 */
-(NSString*)doDecEncryptHex:(NSString *)encryptStr;

@end
