//
//  NSString+BWTPad.h
//  TripleDES
//
//  Created by 徐结兵 on 2018/5/16.
//  Copyright © 2018年 八维通. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (BWTPad)

+ (NSString *)leftPad:(NSString *)string
                 size:(int)size
            padString:(NSString *)padString;

@end
