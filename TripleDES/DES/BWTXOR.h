//
//  BWTXOR.h
//  BWTRideCodeSDK
//  对相同长度字符串进行异或运算
//  Created by 徐结兵 on 2018/5/14.
//  Copyright © 2018年 八维通. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface BWTXOR : NSObject

/**
 对相同长度字符串进行异或运算

 @param pan 待异或字符串
 @param pinv 待异或字符串
 @return 异或后的字符串
 */
+ (NSString *)pinxCreator:(NSString *)pan withPinv:(NSString *)pinv;

@end
