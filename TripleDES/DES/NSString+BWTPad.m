//
//  NSString+BWTPad.m
//  TripleDES
//
//  Created by 徐结兵 on 2018/5/16.
//  Copyright © 2018年 八维通. All rights reserved.
//

#import "NSString+BWTPad.h"

static int PAD_LIMIT = 8192;

@implementation NSString (BWTPad)

+ (NSString *)leftPad:(NSString *)string
                 size:(int)size
            padString:(NSString *)padString {
    if (string.length == 0) {
        return nil;
    }
    if (padString.length == 0) {
        padString = @" ";
    }

    NSUInteger padStringLen = padString.length;
    NSUInteger stringLen = string.length;
    NSUInteger pads = size - stringLen;
    if (pads <= 0) {
        return string; // returns original String when possible
    }
    if (padStringLen == 1 && pads <= PAD_LIMIT) {
        char padStringChars[padStringLen];
        memcpy(padStringChars, [padString cStringUsingEncoding:NSASCIIStringEncoding], 2 * [padString length]);
        char padChar = padStringChars[0];
        return [self p_leftPad:string size:size padChar:padChar];
    }
    
    if (pads == padStringLen) {
        return [NSString stringWithFormat:@"%@%@", padString, string];
    } else if (pads < padStringLen) {
        return [NSString stringWithFormat:@"%@%@", [padString substringToIndex:pads], string];
    } else {
        char padding[pads];
        char padChars[padStringLen];
        memcpy(padChars, [padString cStringUsingEncoding:NSASCIIStringEncoding], 2 * [padString length]);
        for (int i = 0; i < pads; i++) {
            padding[i] = padChars[i % padStringLen];
        }
        NSString *paddingString = [[NSString alloc]initWithCString:padding encoding:NSASCIIStringEncoding];
        return [NSString stringWithFormat:@"%@%@", paddingString, string];
    }
}

+ (NSString *)p_leftPad:(NSString *)string
                   size:(int)size
                padChar:(char)padChar {
    if (string.length == 0) {
        return nil;
    }
    NSInteger pads = size - string.length;
    if (pads <= 0) {
        return string;
    }
    if (pads > PAD_LIMIT) {
        NSString *charString = [NSString stringWithFormat:@"%c", padChar];
        return [self leftPad:string size:size padString:charString];
    }
    NSString *paddingString = [self p_padding:pads padChar:padChar];
    return [NSString stringWithFormat:@"%@%@", paddingString, string];
}

+ (NSString *)p_padding:(NSInteger)repeat
                padChar:(char)padChar {
    NSString *string = @"";
    for (int i =0; i < repeat; i ++) {
        NSString *charString = [NSString stringWithFormat:@"%c", padChar];
        string = [NSString stringWithFormat:@"%@%@", string, charString];
    }
    return string;
//    char buf[repeat];
//    for (int i = 0; i < sizeof(buf); i ++ ) {
//        buf[i] = padChar;
//    }
//    NSString *string = [[NSString alloc] initWithCString:buf encoding:NSASCIIStringEncoding];
//    return string;
}


@end
