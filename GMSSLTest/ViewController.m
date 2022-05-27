//
//  ViewController.m
//  GMSSLTest
//
//  Created by 杨颖 on 2020/1/10.
//  Copyright © 2020 杨颖. All rights reserved.
//

#import "ViewController.h"
#import "GMSm2Utils.h"
@interface ViewController ()
@property (nonatomic,copy) NSString *publicKey;
@property (nonatomic,copy) NSString *privateKey;

@property (weak, nonatomic) IBOutlet UITextField *encryptTextField;
@property (weak, nonatomic) IBOutlet UILabel *encryptHexLabel;
@property (weak, nonatomic) IBOutlet UILabel *decryptResultLabel;

@property (weak, nonatomic) IBOutlet UILabel *decryptLabel;
@end

@implementation ViewController


- (IBAction)clickToEncrypt:(id)sender {
    NSString *enString = [GMSm2Utils encryptText:self.encryptTextField.text publicKey:self.publicKey];
    
    self.encryptHexLabel.text = enString;
}


- (IBAction)clickToDecrypt:(id)sender {
    NSString *content = [GMSm2Utils decryptToText:self.encryptHexLabel.text privateKey:self.privateKey];
    
    self.decryptLabel.text = content;
    
    if (content != nil && [content isEqualToString:self.encryptTextField.text]) {
        self.decryptResultLabel.text = @"解密成功";
        self.decryptResultLabel.textColor = [UIColor grayColor];
        self.decryptResultLabel.backgroundColor = UIColor.greenColor;
    }else {
        self.decryptResultLabel.text = @"解密失败";
        self.decryptResultLabel.textColor = [UIColor grayColor];
        self.decryptResultLabel.backgroundColor = UIColor.redColor;
    }
}

- (void)viewDidLoad {
    [super viewDidLoad];
//    GMSM2Manager *sm2Manager = [[GMSM2Manager alloc] init];
//    [sm2Manager test];
//    NSString * message = @"我爱北京天安门, 12 34 ~~~ 天安门上太阳升!!!!!!";
//
//    NSDictionary *dict = @{@"aasd":@"asdsa",@"13123":@"叫"};
//
//    [ViewController dictionaryToJson:dict];
//
//    NSString * eckey0 = @"04D5FB788A7FA009758083427EFBC10304618A3E75F6EB47870BC0A72A92EC93C2812E38DCC0EED61BDCA12F9C16232D1DABC9D7B3E614D0D1E7007C343CABC0AE";
//
//    NSString *eckey1 = @"00CB64E50DB6C40C4F9D738B155729726F3A98B068C4CCEC9C89D37E729A8E1558";
    
    self.publicKey = @"04D5FB788A7FA009758083427EFBC10304618A3E75F6EB47870BC0A72A92EC93C2812E38DCC0EED61BDCA12F9C16232D1DABC9D7B3E614D0D1E7007C343CABC0AE";
    
    self.privateKey = @"00CB64E50DB6C40C4F9D738B155729726F3A98B068C4CCEC9C89D37E729A8E1558";
    
//    // 字典转字符串
//    NSString *dictString = [ViewController dictionaryToJson:dict];
//
//    NSString *enString = [GMSm2Utils encryptText:dictString publicKey:eckey0];
//
//    NSString *deString = [GMSm2Utils decryptToText:enString privateKey:eckey1];
//
//    NSLog(@"加密后的密文=%@",enString);
//
//    if ([deString isEqualToString:dictString]) {
//        NSLog(@"解密成功");
//    }else {
//        NSLog(@"解密失败");
//    }
}


+(NSString*)dictionaryToJson:(NSDictionary *)dic
{
    NSError *parseError = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dic options:NSJSONWritingPrettyPrinted error:&parseError];
    
    return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}


+ (NSDictionary *)dictionaryWithJsonString:(NSString *)jsonString
{
    if (jsonString == nil) {
        return nil;
    }
    NSData *jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    NSError *err;
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:jsonData options:NSJSONReadingMutableContainers error:&err];
    if(err) {
        NSLog(@"json解析失败：%@",err);
        return nil;
    }
    return dic;
}

@end
