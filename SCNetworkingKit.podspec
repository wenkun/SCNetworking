#
#  Be sure to run `pod spec lint SCNetworking.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see http://docs.cocoapods.org/specification.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#
# 2019101601



Pod::Spec.new do |s|

  s.name         = "SCNetworkingKit"
  s.version      = "0.1.1"
  s.summary      = "网络请求组件"
  s.description  = <<-DESC
                    支持get，post，upload,put请求，使用URLSession
                   DESC
  s.homepage     = "https://10.199.96.150/iOS_pods/SCNetworking.git"
  s.license      = "MIT"
  s.author             = { "李伯波" => "libaibo87@163.com" }
  s.platform     = :ios, "9.0"
  s.source       = { :git => "https://github.com/wenkun/SCNetworking.git", :tag => "#{s.version}" }
  # s.source_files  = "./","*.{h,m}"
  s.vendored_frameworks = ['Debug-iphoneos/SCNetworkingKit.framework']
  s.framework  = "Foundation"

end
