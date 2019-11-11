1、引入方法
pod 'SCNetworking', :git => 'https://10.159.46.130/iOS_pods/SCNetworking.git'

2、代码使用例子
[SCNetworking post:@"http://xxxx" header:@{} parameters:nil completionSuccess:^(NSURLResponse *response, NSDictionary *responseDictionary) {

} failed:^(NSError *error) {

}];
[SCNetworking post:^(NSMutableURLRequest *batchRequest) {
batchRequest.URL = [NSURL URLWithString:@"http://xxxx"];
batchRequest.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{@"parent_id":@""} options:NSJSONWritingPrettyPrinted error:nil];
} completionSuccess:^(NSURLResponse *response, NSDictionary *responseDictionary) {
NSLog(@"%@",responseDictionary);
} failed:^(NSError *error) {
NSLog(@"%@",error);
}];

3、更新
pod repo push PodSpecRepo SCNetworking.podspec --sources='https://10.199.96.150/iOS_pods/PodSpecRepo.git,https://github.com/CocoaPods/Specs' --allow-warnings --use-libraries
