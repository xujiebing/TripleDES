//
//  DBDESManager.m
//  TripleDES
//
//  Created by 徐结兵 on 2019/7/8.
//  Copyright © 2019 徐结兵. All rights reserved.
//

#import "DBDESManager.h"
#import <CommonCrypto/CommonCryptor.h>
#import "NSData+BWTBase64.h"
#import "NSString+BWTPad.h"
#import "BWTXOR.h"

#define ISNIL(x) ((x) == nil ? @"" : (x))

static unsigned char ip[] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52,
    44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48,
    40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35,
    27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31,
    23, 15, 7};
static unsigned char _ip[] = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7,
    47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45,
    13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11,
    51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49,
    17, 57, 25};

// 每次密钥循环左移位数
static unsigned char LS[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

static NSString *kBWTDESOffSet = @"abcdefgh";
static NSMutableArray *subKey = nil;

@implementation DBDESManager

#pragma mark - 公告方法

+ (NSString *)encryptString:(NSString *)string
                  secretKey:(NSString *)secretKey {
    NSString *encryptString = nil;
    NSMutableArray *temp = [[NSMutableArray alloc] initWithCapacity:64];
    NSArray *data = [self p_string2Binary:string];
    // 第一步初始置
    data = [self p_changeIP:data];
    NSMutableArray *left = [[NSMutableArray alloc] initWithCapacity:17];
    NSMutableArray *right = [[NSMutableArray alloc] initWithCapacity:17];
    for (int i = 0; i < 32; i ++ ) {
        NSString *leftObj = [data objectAtIndex:i];
        NSString *rightObj = [data objectAtIndex:i + 32];
        // left
        NSMutableArray *leftSub0 = [left firstObject];
        if (leftSub0.count == 0) {
            leftSub0 = [[NSMutableArray alloc] initWithArray:@[ISNIL(leftObj)]];
            [left addObject:leftSub0];
        } else {
            [leftSub0 addObject:leftObj];
            [left replaceObjectAtIndex:0 withObject:leftSub0];
        }
        // right
        NSMutableArray *rightSub0 = [right firstObject];
        if (rightSub0.count == 0) {
            rightSub0 = [[NSMutableArray alloc] initWithArray:@[ISNIL(rightObj)]];
            [right addObject:rightSub0];
        } else {
            [rightSub0 addObject:rightObj];
            [right replaceObjectAtIndex:0 withObject:rightSub0];
        }
    }
    
    [self p_setKey:secretKey];
    for (int i = 1; i < 17; i ++ ) {
        // 获取(48bit)的轮子密
        NSMutableArray *key = [subKey objectAtIndex:i - 1];
        // L1 = R0
        NSMutableArray *leftObj = [right objectAtIndex:i - 1];
        [left addObject:leftObj];
        // R1 = L0 ^ f(R0,K1)
        NSMutableArray *fTemp = [self p_f:leftObj K:key]; // 32bit
        NSMutableArray *leftSub = [left objectAtIndex:i - 1];
        NSArray *diffOrArray = [self p_diffOr:leftSub source2:fTemp];
        [right addObject:ISNIL(diffOrArray)];
    }
    
    // 组合的时候，左右调换**************************************************
    NSMutableArray *leftSub = [left objectAtIndex:16];
    NSMutableArray *rightSub = [right objectAtIndex:16];
    if (!rightSub || !leftSub) {
        return nil;
    }
    for (int i = 0; i < 32; i ++) {
        NSString *rightObj = [rightSub objectAtIndex:i];
        [temp addObject:ISNIL(rightObj)];
    }
    for (int i = 0; i < 32; i ++) {
        NSString *leftObj = [leftSub objectAtIndex:i];
        [temp addObject:ISNIL(leftObj)];
    }
    temp = [self p_changeInverseIP:temp];
    NSString *intArr2Str = [self p_intArr2Str:temp];
    encryptString = [self p_binary2ASC:intArr2Str];
    return encryptString;
}

+ (NSString *)decryptString:(NSString *)string
                  secretKey:(NSString *)secretKey {
    NSString *decryptString = @"";
    NSMutableArray *data = [self p_string2Binary:string]; // 64bit
    // 第一步初始置
    data = [self p_changeIP:data];
    
    NSMutableArray *left = [[NSMutableArray alloc] initWithCapacity:32];
    NSMutableArray *right = [[NSMutableArray alloc] initWithCapacity:32];
    NSMutableArray *tmp = nil;
    for (int i = 0; i < 32; i ++ ) {
        NSString *leftObj = [data objectAtIndex:i];
        NSString *rightObj = [data objectAtIndex:i + 32];
        [left addObject:ISNIL(leftObj)];
        [right addObject:ISNIL(rightObj)];
    }
    
    [self p_setKey:secretKey];
    for (int i = 16; i > 0; i -- ) {
        // 获取(48bit)的轮子密
        NSMutableArray *sKey = [subKey objectAtIndex:i - 1];
        tmp = left;
        // R1 = L0
        left = right;
        // L1 = R0 ^ f(L0,K1)
        NSMutableArray *fTemp = [self p_f:right K:sKey]; // 32bit
        right = [self p_diffOr:tmp source2:fTemp];
    }
    
    // 组合的时候，左右调换**************************************************
    for (int i = 0; i < 32; i ++) {
        NSString *rightObj = [right objectAtIndex:i];
        [data replaceObjectAtIndex:i withObject:ISNIL(rightObj)];
    }
    for (int i = 0; i < 32; i ++) {
        NSString *leftObj = [left objectAtIndex:i];
        [data replaceObjectAtIndex:i + 32 withObject:ISNIL(leftObj)];
    }
    data = [self p_changeInverseIP:data];
    for (int i = 0; i < data.count; i ++) {
        decryptString = [NSString stringWithFormat:@"%@%@", decryptString, [data objectAtIndex:i]];
    }
    decryptString = [self p_binary2ASC:decryptString];
    return decryptString;
}

+ (NSString *)triplrDESWithString:(NSString *)string
                        secretKey:(NSString *)secretKey
                             type:(DBDESType)type {
    NSString *temp = nil;
    NSString *K1 = [secretKey substringWithRange:NSMakeRange(0, secretKey.length / 2)];
    NSString *K2 = [secretKey substringFromIndex:secretKey.length / 2];
    
    if (type == DBDESEncrypt) {
        temp = [self encryptString:string secretKey:K1];
        temp = [self decryptString:temp secretKey:K2];
        temp = [self encryptString:temp secretKey:K1];
    }
    if (type == DBDESDecrypt) {
        temp = [self decryptString:string secretKey:K1];
        temp = [self encryptString:temp secretKey:K2];
        temp = [self decryptString:temp secretKey:K1];
    }
    return temp;
}

#pragma mark - 私有方法

/**
 将int类型数组拼接成字符串
 
 @param arr int类型数组
 @return 拼接完成之后的字符串
 */
+ (NSString *)p_intArr2Str:(NSArray *)arr {
    NSString *string = [arr componentsJoinedByString:@""];
    return string;
}

/**
 将二进制字符串转换成十六进制字符
 
 @param s 二进制字符串
 @return 十六进制字符
 */
+ (NSString *)p_binary2ASC:(NSString *)s {
    NSString *str = @"";
    NSInteger ii = 0;
    NSInteger len = s.length;
    // 不够4bit左补0
    if (len % 4 != 0) {
        while (ii < 4 - len % 4) {
            s = [NSString stringWithFormat:@"0%@", s];
            ii++;  // add by wangjie
        }
    }
    for (int i = 0; i < len / 4; i++) {
        NSString *subString = [s substringWithRange:NSMakeRange(i * 4, 4)];
        str = [NSString stringWithFormat:@"%@%@", str, [self p_binary2Hex:subString]];
    }
    return str;
}

/**
 s位长度的二进制字符串
 
 @param s s
 @return 二进制字符串
 */
+ (NSString *)p_binary2Hex:(NSString *)s {
    NSInteger len = s.length;
    NSInteger result = 0;
    NSInteger k = 0;
    if (len > 4) {
        return nil;
    }
    for (NSInteger i = len; i > 0; i--) {
        NSString *subString = [s substringWithRange:NSMakeRange(i - 1, 1)];
        result = result + [[self p_toDecimalSystemWithBinarySystem:subString] integerValue] * [self p_getXY:2 y:k];
        k++;
    }
    switch (result) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
            return [NSString stringWithFormat:@"%ld", (long)result];
        case 10:
            return @"A";
        case 11:
            return @"B";
        case 12:
            return @"C";
        case 13:
            return @"D";
        case 14:
            return @"E";
        case 15:
            return @"F";
        default:
            return nil;
    }
}

/**
 返回x的y次方
 
 @param x x
 @param y y
 @return x的y次方
 */
+ (NSInteger)p_getXY:(NSInteger)x y:(NSInteger)y {
    NSInteger temp = x;
    if (y == 0) {
        x = 1;
    }
    for (int i = 2; i <= y; i++) {
        x *= temp;
    }
    return x;
}

/**
 IP-1逆置
 
 @param source source
 @return dest
 */
+ (NSMutableArray *)p_changeInverseIP:(NSArray *)source {
    NSInteger count = 64;
    NSMutableArray *dest = [[NSMutableArray alloc] initWithCapacity:count];
    for (int i = 0; i < count; i ++ ) {
        NSString *obj = source[_ip[i] - 1];
        [dest addObject:obj];
    }
    return dest;
}

/**
 p_f
 
 @param R R(2bit)
 @param K K(48bit的轮子密)
 @return 32bit
 */
+ (NSMutableArray *)p_f:(NSArray *)R K:(NSArray *)K {
    // 先将输入32bit扩展8bit
    NSMutableArray *expendR = [self p_expend:R]; // 48bit
    // 与轮子密钥进行异或运
    NSMutableArray *temp = [self p_diffOr:expendR source2:K];
    // 压缩2bit
    NSMutableArray *dest = [self p_press:temp];
    return dest;
}

/**
 8bit压缩2bit
 
 @param source 48bit
 @return R(32bit) B=E(R)⊕K，将48 位的B 分成8 个分组，B=B1B2B3B4B5B6B7B8
 */
+ (NSMutableArray *)p_press:(NSArray *)source {
    NSMutableArray *temp = [[NSMutableArray alloc] initWithCapacity:8];
    
    NSArray *s = [self p_s];
    for (int i = 0; i < 8; i ++) {
        NSMutableArray *tempSub = [[NSMutableArray alloc] initWithCapacity:6];
        for (int j = 0; j < 6; j ++) {
            NSString *obj = [source objectAtIndex:6 * i + j];
            [tempSub addObject:ISNIL(obj)];
        }
        [temp addObject:tempSub];
    }
    
    NSString *str = @"";
    for (int i = 0; i < 8; i ++ ) {
        // (16)
        NSMutableArray *tempSub = [temp objectAtIndex:i];
        NSInteger x = [[tempSub objectAtIndex:0] integerValue] * 2 + [[tempSub objectAtIndex:5] integerValue];
        // (2345)
        NSInteger y = [[tempSub objectAtIndex:1] integerValue] * 8 + [[tempSub objectAtIndex:2] integerValue] * 4 + [[tempSub objectAtIndex:3] integerValue] * 2 + [[tempSub objectAtIndex:4] integerValue];
        NSInteger val = [[[[s objectAtIndex:i] objectAtIndex:x] objectAtIndex:y] integerValue];
        NSString *ch = [self p_intToHex:val];
        str = [NSString stringWithFormat:@"%@%@", str, ch];
    }
    NSMutableArray *ret = [self p_string2Binary:str];
    // 置换P
    ret  =[self p_dataP:ret];
    return ret;
}

/**
 将int转换成Hex
 
 @param i int
 @return Hex
 */
+ (NSString *)p_intToHex:(NSInteger)i {
    switch (i) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
            return [NSString stringWithFormat:@"%ld", i];
        case 10:
            return @"A";
        case 11:
            return @"B";
        case 12:
            return @"C";
        case 13:
            return @"D";
        case 14:
            return @"E";
        case 15:
            return @"F";
        default:
            return nil;
    }
}

/**
 两个等长的数组做异或
 
 @param source1 source1
 @param source2 source2
 @return 异或之后的数组
 */
+ (NSMutableArray *)p_diffOr:(NSArray *)source1 source2:(NSArray *)source2 {
    NSInteger len = source1.count;
    NSMutableArray *dest = [[NSMutableArray alloc] initWithCapacity:len];
    for (int i = 0; i < len; i++) {
        NSString *a = [source1 objectAtIndex:i];
        NSString *b = [source2 objectAtIndex:i];
        NSString *ab = [BWTXOR pinxCreator:a withPinv:b];
        [dest addObject:ISNIL(ab)];
    }
    return dest;
}

/**
 置换P(32bit)
 
 @param source source
 @return dest
 */
+ (NSMutableArray *)p_dataP:(NSArray *)source {
    NSMutableArray *dest = [[NSMutableArray alloc] initWithCapacity:32];
    NSArray *temp = @[@16, @7, @20, @21, @29, @12, @28, @17, @1, @15, @23, @26, @5, @18, @31,
                      @10, @2, @8, @24, @14, @32, @27, @3, @9, @19, @13, @30, @6, @22, @11, @4, @25];
    NSInteger len = source.count;
    for (int i = 0; i < len; i ++ ) {
        NSNumber *number = [temp objectAtIndex:i];
        NSInteger index = number.integerValue - 1;
        NSString *obj = [source objectAtIndex:index];
        [dest addObject:ISNIL(obj)];
    }
    return dest;
}

/**
 2bit扩展8bit
 
 @param source 2bit
 @return 8bit
 */
+ (NSMutableArray *)p_expend:(NSArray *)source {
    NSMutableArray *ret = [[NSMutableArray alloc] initWithCapacity:48];
    NSArray *temp = @[@32, @1, @2, @3, @4, @5, @4, @5, @6, @7, @8, @9, @8, @9, @10, @11, @12,
                      @13, @12, @13, @14, @15, @16, @17, @16, @17, @18, @19, @20, @21, @20, @21, @22,
                      @23, @24, @25, @24, @25, @26, @27, @28, @29, @28, @29, @30, @31, @32, @1];
    for (int i = 0; i < 48; i++) {
        NSNumber *number = [temp objectAtIndex:i];
        NSInteger index = number.integerValue - 1;
        NSString *obj = [source objectAtIndex:index];
        [ret addObject:ISNIL(obj)];
    }
    return ret;
}

/**
 获取轮子密钥(48bit)
 
 @param source source
 */
+ (void)p_setKey:(NSString *)source {
    if (subKey.count > 0) {
        subKey = [[NSMutableArray alloc] initWithCapacity:16];
    }
    // 装换4bit
    NSArray *temp = [self p_string2Binary:source];
    // 6bit均分成两部分
    NSMutableArray *left = [[NSMutableArray alloc] initWithCapacity:28];
    NSMutableArray *right = [[NSMutableArray alloc] initWithCapacity:28];
    // 经过PC-14bit转换6bit
    NSMutableArray *temp1 =  [self p_keyPC_1:temp];
    // 将经过转换的temp1均分成两部分
    for (int i = 0; i < 28; i++) {
        NSString *leftObj = [temp1 objectAtIndex:i];
        NSString *rightObj = [temp1 objectAtIndex:i + 28];
        [left addObject:ISNIL(leftObj)];
        [right addObject:ISNIL(rightObj)];
    }
    // 经过16次循环左移，然后PC-2置换
    for (int i = 0; i < 16; i++) {
        left = [self p_keyLeftMove:left i:LS[i]];
        right = [self p_keyLeftMove:right i:LS[i]];
        for (int j = 0; j < 28; j++) {
            NSString *leftObj = [left objectAtIndex:j];
            NSString *rightObj = [right objectAtIndex:j];
            [temp1 replaceObjectAtIndex:j withObject:ISNIL(leftObj)];
            [temp1 replaceObjectAtIndex:j + 28 withObject:ISNIL(rightObj)];
        }
        if (!subKey) {
            subKey = [[NSMutableArray alloc] initWithCapacity:16];
        }
        NSMutableArray *subArray = [self p_keyPC_2:temp1];
        [subKey addObject:ISNIL(subArray)];
    }
}

/**
 将密钥循环左移i
 
 @param source 二进制密钥数
 @param i 循环左移位数
 @return 左移后的密钥
 */
+ (NSMutableArray *)p_keyLeftMove:(NSArray *)source i:(int)i {
    NSInteger temp = 0;
    NSInteger len = source.count;
    NSInteger ls = LS[i];
    NSMutableArray *source1 = [[NSMutableArray alloc] initWithArray:source];
    for (int k = 0; k < ls; k++) {
        temp = [[source1 objectAtIndex:0] integerValue];
        for (int j = 0; j < len - 1; j++) {
            NSString *obj = [source1 objectAtIndex:j + 1];
            [source1 replaceObjectAtIndex:j withObject:ISNIL(obj)];
        }
        NSInteger index = len - 1;
        NSString *tempString = [NSString stringWithFormat:@"%ld", (long)temp];
        [source1 replaceObjectAtIndex:index withObject:ISNIL(tempString)];
    }
    return source1;
}

/**
 6bit的密钥转换成48bit
 
 @param source 6bit的密钥
 @return 48bit的密钥
 */
+ (NSMutableArray *)p_keyPC_2:(NSArray *)source {
    NSMutableArray *dest = [[NSMutableArray alloc] initWithCapacity:48];
    NSArray *temp = @[@14, @17, @11, @24, @1, @5,
                      @3, @28, @15, @6, @21, @10,
                      @23, @19, @12, @4, @26, @8,
                      @16, @7, @27, @20, @13, @2,
                      @41, @52, @31, @37, @47, @55,
                      @30, @40, @51, @45, @33, @48,
                      @44, @49, @39, @56, @34, @53,
                      @46, @42, @50, @36, @29, @32];
    for (int i = 0; i < 48; i ++ ) {
        NSNumber *number = [temp objectAtIndex:i];
        NSInteger index = number.integerValue - 1;
        NSString *obj = [source objectAtIndex:index];
        [dest addObject:ISNIL(obj)];
    }
    return dest;
}

/**
 4bit的密钥转换成56bit
 
 @param source source 4bit
 @return 56bit
 */
+ (NSMutableArray *)p_keyPC_1:(NSArray *)source {
    NSMutableArray *dest = [[NSMutableArray alloc] initWithCapacity:56];
    NSArray *temp = @[@57, @49, @41, @33, @25, @17, @9,
                      @1, @58, @50, @42, @34, @26, @18,
                      @10, @2, @59, @51, @43, @35, @27,
                      @19, @11, @3, @60, @52, @44, @36,
                      @63, @55, @47, @39, @31, @23, @15,
                      @7, @62, @54, @46, @38, @30, @22,
                      @14, @6, @61, @53, @45, @37, @29,
                      @21, @13, @5, @28, @20, @12, @4];
    for (int i = 0; i < 56; i++) {
        NSNumber *number = [temp objectAtIndex:i];
        NSInteger index = number.integerValue - 1;
        NSString *obj = [source objectAtIndex:index];
        [dest addObject:ISNIL(obj)];
    }
    return dest;
}

/**
 IP初始置换
 */
+ (NSMutableArray *)p_changeIP:(NSArray *)source {
    NSInteger count = 64;
    NSMutableArray *dest = [[NSMutableArray alloc] initWithCapacity:count];
    for (int i = 0; i < count; i ++ ) {
        NSString *obj = source[ip[i] - 1];
        [dest addObject:obj];
    }
    return dest;
}

/**
 将字符串转换成二进制数组
 
 @param source 16字节
 @return string
 */
+ (NSMutableArray *)p_string2Binary:(NSString *)source {
    NSMutableArray *temp = [NSMutableArray arrayWithCapacity:source.length];
    // 遍历字符串，按字符来遍历。每个字符将通过block参数中的substring传出
    [source enumerateSubstringsInRange:NSMakeRange(0, source.length) options:NSStringEnumerationByComposedCharacterSequences usingBlock:^(NSString *substring, NSRange substringRange, NSRange enclosingRange, BOOL *stop) {
        [temp addObject:substring];
    }];
    
    NSString *sb = @"";
    for (int i = 0; i < source.length; i ++ ) {
        NSString *charString = [NSString stringWithFormat:@"%@",temp[i]];
        NSInteger charInt = [self p_intFromHexString:charString];
        NSString *binaryString = [self p_toBinarySystemWithDecimalSystem:charInt];
        NSString *pad = [NSString leftPad:binaryString size:4 padString:@"0"];
        sb = [NSString stringWithFormat:@"%@%@", sb, pad];
    }
    NSMutableArray *array = [NSMutableArray arrayWithCapacity:0];
    // 遍历字符串，按字符来遍历。每个字符将通过block参数中的substring传出
    [sb enumerateSubstringsInRange:NSMakeRange(0, sb.length) options:NSStringEnumerationByComposedCharacterSequences usingBlock:^(NSString *substring, NSRange substringRange, NSRange enclosingRange, BOOL *stop) {
        [array addObject:substring];
    }];
    return array;
}

/**
 16进制数字转换成10进制数字
 
 @param hexString 16进制
 @return 10进制
 */
+ (NSInteger)p_intFromHexString:(NSString *)hexString {
    // 为空,直接返回.
    if (!hexString) {
        return 0;
    }
    NSScanner * scanner = [NSScanner scannerWithString:hexString];
    unsigned int intValue;
    [scanner scanHexInt:&intValue];
    return intValue;
}


/**
 10进制转2进制
 
 @param decimal 10进制
 @return 2进制
 */
+ (NSString *)p_toBinarySystemWithDecimalSystem:(NSInteger)decimal {
    NSInteger num = decimal;
    // 余数
    NSInteger remainder = 0;
    // 除数
    NSInteger divisor = 0;
    NSString *prepare = @"";
    
    while (true) {
        remainder = num%2;
        divisor = num/2;
        num = divisor;
        prepare = [prepare stringByAppendingFormat:@"%ld",(long)remainder];
        if (divisor == 0) {
            break;
        }
    }
    NSString * result = @"";
    for (NSInteger i = prepare.length - 1; i >= 0; i --) {
        result = [result stringByAppendingFormat:@"%@",
                  [prepare substringWithRange:NSMakeRange(i , 1)]];
    }
    return result;
}

/**
 2进制转10进制
 
 @param binary 2进制
 @return 10进制
 */
+ (NSString *)p_toDecimalSystemWithBinarySystem:(NSString *)binary {
    int ll = 0 ;
    int  temp = 0 ;
    for (int i = 0; i < binary.length; i ++) {
        temp = [[binary substringWithRange:NSMakeRange(i, 1)] intValue];
        temp = temp * powf(2, binary.length - i - 1);
        ll += temp;
    }
    NSString * result = [NSString stringWithFormat:@"%d",ll];
    return result;
}

+ (NSArray *)p_s {
    /**
     * **************************压缩替换S-Box*************************************************
     */
    NSArray *array = @[@[/* s1 */
                           @[@14, @4, @13, @1, @2, @15, @11, @8, @3, @10, @6, @12, @5, @9, @0, @7],
                           @[@0, @15, @7, @4, @14, @2, @13, @1, @10, @6, @12, @11, @9, @5, @3, @8],
                           @[@4, @1, @14, @8, @13, @6, @2, @11, @15, @12, @9, @7, @3, @10, @5, @0],
                           @[@15, @12, @8, @2, @4, @9, @1, @7, @5, @11, @3, @14, @10, @0, @6, @13]
                           ],
                       @[/* s2 */
                           @[@15, @1, @8, @14, @6, @11, @3, @4, @9, @7, @2, @13, @12, @0, @5, @10],
                           @[@3, @13, @4, @7, @15, @2, @8, @14, @12, @0, @1, @10, @6, @9, @11, @5],
                           @[@0, @14, @7, @11, @10, @4, @13, @1, @5, @8, @12, @6, @9, @3, @2, @15],
                           @[@13, @8, @10, @1, @3, @15, @4, @2, @11, @6, @7, @12, @0, @5, @14, @9],
                           ],
                       @[/* s3 */
                           @[@10, @0, @9, @14, @6, @3, @15, @5, @1, @13, @12, @7, @11, @4, @2, @8],
                           @[@13, @7, @0, @9, @3, @4, @6, @10, @2, @8, @5, @14, @12, @11, @15, @1],
                           @[@13, @6, @4, @9, @8, @15, @3, @0, @11, @1, @2, @12, @5, @10, @14, @7],
                           @[@1, @10, @13, @0, @6, @9, @8, @7, @4, @15, @14, @3, @11, @5, @2, @12]
                           ],
                       @[/* s4 */
                           @[@7, @13, @14, @3, @0, @6, @9, @10, @1, @2, @8, @5, @11, @12, @4, @15],
                           @[@13, @8, @11, @5, @6, @15, @0, @3, @4, @7, @2, @12, @1, @10, @14, @9],// erorr
                           @[@10, @6, @9, @0, @12, @11, @7, @13, @15, @1, @3, @14, @5, @2, @8, @4],
                           @[@3, @15, @0, @6, @10, @1, @13, @8, @9, @4, @5, @11, @12, @7, @2, @14]
                           ],
                       @[/* s5 */
                           @[@2, @12, @4, @1, @7, @10, @11, @6, @8, @5, @3, @15, @13, @0, @14, @9],
                           @[@14, @11, @2, @12, @4, @7, @13, @1, @5, @0, @15, @10, @3, @9, @8, @6],
                           @[@4, @2, @1, @11, @10, @13, @7, @8, @15, @9, @12, @5, @6, @3, @0, @14],
                           @[@11, @8, @12, @7, @1, @14, @2, @13, @6, @15, @0, @9, @10, @4, @5, @3]
                           ],
                       @[/* s6 */
                           @[@12, @1, @10, @15, @9, @2, @6, @8, @0, @13, @3, @4, @14, @7, @5, @11],
                           @[@10, @15, @4, @2, @7, @12, @9, @5, @6, @1, @13, @14, @0, @11, @3, @8],
                           @[@9, @14, @15, @5, @2, @8, @12, @3, @7, @0, @4, @10, @1, @13, @11, @6],
                           @[@4, @3, @2, @12, @9, @5, @15, @10, @11, @14, @1, @7, @6, @0, @8, @13]
                           ],
                       @[/* s7 */
                           @[@4, @11, @2, @14, @15, @0, @8, @13, @3, @12, @9, @7, @5, @10, @6, @1],
                           @[@13, @0, @11, @7, @4, @9, @1, @10, @14, @3, @5, @12, @2, @15, @8, @6],
                           @[@1, @4, @11, @13, @12, @3, @7, @14, @10, @15, @6, @8, @0, @5, @9, @2],
                           @[@6, @11, @13, @8, @1, @4, @10, @7, @9, @5, @0, @15, @14, @2, @3, @12]
                           ],
                       @[/* s8 */
                           @[@13, @2, @8, @4, @6, @15, @11, @1, @10, @9, @3, @14, @5, @0, @12, @7],
                           @[@1, @15, @13, @8, @10, @3, @7, @4, @12, @5, @6, @11, @0, @14, @9, @2],
                           @[@7, @11, @4, @1, @9, @12, @14, @2, @0, @6, @10, @13, @15, @3, @5, @8],
                           @[@2, @1, @14, @7, @4, @10, @8, @13, @15, @12, @9, @0, @3, @5, @6, @11]
                           ],
                       ];
    return array;
}

@end
