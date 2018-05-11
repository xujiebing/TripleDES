//
//  ViewController.m
//  RAC+SHA1WithRSA
//
//  Created by 徐结兵 on 2018/5/8.
//  Copyright © 2018年 xujiebing. All rights reserved.
//

#import "ViewController.h"
#import "BWTTripleDES.h"
#import "AlertTool.h"

static NSString *kEncryptString = @"待加密信息";
static NSString *kEncrypt = nil;

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
}

// 加密
- (IBAction)encryptWith3DES:(id)sender {
    NSString *encrypt = [BWTTripleDES encryptString:kEncryptString];
    kEncrypt = encrypt;
    NSLog(@"******************** \n\n %@ \n\n **********", kEncrypt);
    [AlertTool alertViewWithMessage:kEncrypt];
}

// 解密
- (IBAction)decryptWith3DES:(id)sender {
    if (kEncrypt.length == 0) {
        [AlertTool alertViewWithMessage:@"请先加密"];
        return;
    }
    NSString *decrypt = [BWTTripleDES decryptString:kEncrypt];
    NSString *message = nil;
    if ([decrypt isEqualToString:kEncryptString]) {
        message = @"解密成功";
    } else {
        message = @"解密失败";
    }
    [AlertTool alertViewWithMessage:message];
    NSLog(@"******************** \n\n %@ \n\n **********", message);
}


@end
