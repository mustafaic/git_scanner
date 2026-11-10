# Görev: Mevcut Projenin UI/UX İyileştirmesi ve Tasarım Sistemi Oluşturulması

Sen deneyimli bir Senior UI/UX Designer, Product Designer ve Senior Frontend Engineer olarak hareket edeceksin.

Mevcut geliştirdiğim projenin işlevselliğini ve teknik mimarisini koruyarak arayüzünü çok daha profesyonel, modern, tutarlı ve estetik bir seviyeye taşımak istiyorum.

Amacım sıfırdan yeni bir proje oluşturmak değil. Mevcut projenin tasarım kalitesini yükseltmek ve bundan sonraki geliştirmelerde de aynı kaliteyi koruyabilecek kalıcı bir tasarım sistemi oluşturmaktır.

## 1. Öncelikle gerekli skill'leri kur

UI/UX ve frontend tasarımı konusunda yetkinliğini artırmak için uygun skill'leri araştır ve projeye entegre et.

Öncelikli olarak şu kaynakları değerlendir:

- Anthropic resmi Frontend Design skill: https://github.com/anthropics/skills/tree/main/skills/frontend-design
- Claude Code resmi plugin ve skill kaynakları.
- Gerekli görürsen design system, accessibility, responsive design ve frontend best practices alanlarında güvenilir ek skill'ler.

Kurulum yaparken:
- Öncelikle resmi ve güvenilir kaynakları tercih et.
- Mevcut kurulu skill'leri kontrol et, aynı skill'i tekrar kurma.
- Gereksiz veya birbiriyle çakışan skill'ler yükleme.
- Kaynağını doğrulayamadığın kodları veya kurulum scriptlerini çalıştırma.
- Skill'lerin gerçekten kullanılabilir olduğunu doğrula.

Bununla birlikte projeye özel bir UI/UX Design System skill'i oluştur.

Bu skill:
- Projenin tasarım dilini tanımlamalı.
- Renk, typography, spacing, component ve layout standartlarını içermeli.
- Yeni sayfa veya component geliştirilirken otomatik olarak dikkate alınmalı.
- Mevcut sayfalardaki görsel tutarsızlıkların giderilmesine yardımcı olmalı.

Claude Code için uygun proje-local skill yapısını kullan. Gerekirse mevcut CLAUDE.md dosyasına tasarım sisteminin kurallarını ekle. Var olan talimatları silme veya üzerine yazma.

## 2. Mevcut projeyi detaylı analiz et

Henüz kodlarda değişiklik yapmadan önce projeyi incele.

Şunları tespit et:

- Kullanılan frontend teknolojileri ve framework.
- Mevcut component mimarisi.
- Sayfalar ve navigasyon yapısı.
- CSS, styling ve UI kütüphaneleri.
- Renk paleti ve typography.
- Tekrarlanan veya tutarsız componentler.
- Responsive tasarım durumu.
- UI/UX açısından zayıf noktalar.
- Kullanılabilirliği ve görsel kaliteyi düşüren tasarım tercihleri.

Mevcut tasarımı bir ürün tasarımcısı gözüyle değerlendir.

## 3. Profesyonel bir Design System oluştur

Projenin amacına ve mevcut kimliğine uygun bir tasarım sistemi oluştur.

Aşağıdaki konularda merkezi ve tutarlı standartlar belirle:

**Visual Identity**
- Primary ve secondary renkler.
- Background ve surface renkleri.
- Typography ve font hiyerarşisi.
- Font ağırlıkları ve boyutları.
- Spacing sistemi.
- Border radius.
- Border ve shadow standartları.
- Icon kullanımı.

**Component System**
- Buttons
- Input fields
- Selects
- Dropdowns
- Cards
- Tables
- Modals
- Badges
- Alerts
- Tooltips
- Navigation
- Sidebar
- Header
- Loading states
- Empty states
- Error states

Bütün componentler aynı tasarım diline sahip olmalı.

Mümkün olduğunca tekrar kullanılabilir componentler oluştur. Renkleri, spacing değerlerini ve diğer tasarım değişkenlerini merkezi tokenlar üzerinden yönet.

## 4. Mevcut arayüzün tasarımını iyileştir

Mevcut sayfaları tek tek incele ve tasarımlarını geliştir.

Özellikle şunlara dikkat et:

- Görsel hiyerarşiyi iyileştir.
- Gereksiz boşlukları ve sıkışık alanları düzenle.
- Sayfa düzenlerini daha dengeli hale getir.
- Typography kullanımını profesyonelleştir.
- Kart, tablo ve form tasarımlarını iyileştir.
- Navigasyon deneyimini geliştir.
- Renk kontrastlarını ve okunabilirliği artır.
- Gereksiz görsel kalabalığı azalt.
- Responsive tasarımı iyileştir.
- Mikro etkileşimleri ve hover/focus durumlarını düzenle.

Bütün sayfalarda aynı design system kullanılmalı. Bir sayfayı iyileştirirken diğer sayfaların tasarım dilinden kopmasına izin verme.

## 5. Tasarım kalitesi için dikkat edeceğin ilkeler

Şu tasarım hatalarından kesinlikle kaçın:

- Her yere gradient eklemek.
- Gereksiz yere aşırı rounded card kullanmak.
- Her elementi farklı renklerle vurgulamak.
- Rastgele spacing değerleri kullanmak.
- Birbirinden bağımsız component tasarımları oluşturmak.
- Her sayfada farklı font ve görsel dil kullanmak.
- Sıradan, birbirinin kopyası AI-generated dashboard tasarımları üretmek.
- Gereksiz animasyonlar ve dikkat dağıtıcı efektler eklemek.
- Sadece güzel görünmesine odaklanıp kullanılabilirliği ihmal etmek.

Tasarım yaklaşımın gerçek bir SaaS ürününün profesyonel tasarım ekibinden çıkmış gibi olmalı.

Tasarım tercihlerinde modern, temiz, dengeli ve işlevsel bir yaklaşım benimse. Projenin kendi karakterini koru; bütün projeleri birbirine benzeyen hazır bir dashboard şablonuna dönüştürme.

## 6. Teknik kurallara uy

Bu görevde mevcut projenin çalışır durumda kalması önceliklidir.

- Mevcut backend kodlarına gereksiz yere müdahale etme.
- API endpointlerini ve veri modellerini değiştirme.
- Authentication ve authorization mekanizmalarını bozma.
- Mevcut işlevleri ve kullanıcı akışlarını koru.
- Çalışan özellikleri kaldırma.
- Mevcut teknoloji yığını yeterliyse yeni framework veya UI kütüphanesine geçme.
- Gereksiz bağımlılık ekleme.
- Componentleri yeniden düzenlerken mevcut davranışlarını koru.
- Var olan testleri çalıştır ve mümkünse yeni UI kontrolleri ekle.

Bir değişiklik mevcut işlevselliği etkileyebilecekse önce riskini değerlendir.

## 7. Uygulama ve kontrol süreci

Aşağıdaki sırayla ilerle:

**Aşama 1:** Skill'leri araştır, kur ve doğrula.

**Aşama 2:** Mevcut projeyi ve tüm sayfaları analiz et.

**Aşama 3:** Tasarım eksikliklerini ve iyileştirme önerilerini belirle.

**Aşama 4:** Projeye özel design system oluştur ve kalıcı hale getir.

**Aşama 5:** Mevcut sayfaları ve ortak componentleri iyileştir.

**Aşama 6:** Uygulamayı çalıştır ve mümkünse browser üzerinden görsel kontrol yap.

**Aşama 7:** Responsive görünümü, etkileşimleri ve mevcut fonksiyonları kontrol et. Tespit ettiğin tasarım hatalarını düzelt.

Her aşamayı gerçekten tamamla. Yalnızca öneri sunmakla yetinme.

## 8. Başarı kriterleri

Çalışmanın sonunda:

1. Projede gerekli UI/UX skill'leri kurulmuş olmalı.
2. Projeye özel kalıcı bir design system bulunmalı.
3. Bütün sayfalar tutarlı bir görsel dile sahip olmalı.
4. Ortak UI componentleri yeniden kullanılabilir olmalı.
5. Arayüz hem masaüstünde hem mobilde düzgün çalışmalı.
6. Mevcut uygulamanın işlevselliği korunmalı.
7. Uygulama görsel olarak önceki halinden belirgin biçimde daha kaliteli olmalı.

**Önemli:** Bu çalışma yalnızca CSS renklerini değiştirmek veya birkaç kartın görünümünü güzelleştirmek değildir. Hedefim bütün ürünün görsel tasarım kalitesini ve kullanıcı deneyimini iyileştirmektir.

Önce mevcut projeyi anla, sonra tasarım sistemini oluştur ve iyileştirmeleri doğrudan mevcut kod tabanında uygula.