//
//  BWTXOR.m
//  BWTRideCodeSDK
//
//  Created by 徐结兵 on 2018/5/14.
//  Copyright © 2018年 八维通. All rights reserved.
//

#import "BWTXOR.h"

@implementation BWTXOR

+ (NSString *)pinxCreator:(NSString *)pan withPinv:(NSString *)pinv {
    if (pan.length != pinv.length) {
        return nil;
    }
    
    const char *panchar = [pan UTF8String];
    const char *pinvchar = [pinv UTF8String];
    
    NSString *temp = [[NSString alloc] init];
    
    for (int i = 0; i < pan.length; i++) {
        int panValue = [self p_charToint:panchar[i]];
        int pinvValue = [self p_charToint:pinvchar[i]];
        temp = [temp stringByAppendingString:[NSString stringWithFormat:@"%X",panValue^pinvValue]];
    }
    return temp;
}

+ (int)p_charToint:(char)tempChar {
    if (tempChar >= '0' && tempChar <='9') {
        return tempChar - '0';
    } else if (tempChar >= 'A' && tempChar <= 'F') {
        return tempChar - 'A' + 10;
    }
    return 0;
}

@end
