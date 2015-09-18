Модуль CTPP 2.8.x для Perl. (Linux)
=====

HTML:CTPP2 заброшен ещё со времён 2011-го года и уже вряд ли будет кем-то поддерживаться. Он не совместим с новыми версиями CTPP2 и содержит в себе некоторые рудименты. 
На основе его был написан новый модуль, который нормально работает с новой версией. 

Плюсы над старой версией:
=====
1. Проще поддерживать
2. Работает нормально с новым CTPP2 2.8.4
3. Исправлена проблема с top-level хэшами, теперь это хэши, а не распакованные отдельные переменные (фатальный баг, всегда бесил)
4. Возможность добавления и удаления своих и системных функций. (киллер фича!)

Т.е. старая версия не поддерживала хэши на верхнем уровне, она их распаковывала в переменные вида:

**Вот такой хэш передан в шаблон:**
```js
{
	"Li" => "-8539464",
	"Link_id" => "294306",
	"Lt" => "2",
}
```

**Вывод старой версии:**
```js
add_url_params = 1;
add_url_params.Li = "-8539464";
add_url_params.Link_id = "294306";
add_url_params.Lt = "2"
```

Это просто список переменных с точкой в своём имени. :(
add_url_params нельзя заюзаь для передачи в JSON(), например. 

**Вывод новой версии:**
```js
add_url_params = {
  'Li' : "-8539464",
  'Link_id' : "294306",
  'Lt' : "2"
}
```
Теперь add_url_params полноценный хэш!

Но при этом больше *не поддерживается* передача переменных с точкой в названии:
```perl
$ctpp2->params({
	"ololo.name" => "ololo"
});
// шаблон
<TMPL_var ololo.name>
```
**Работать больше не будет!11**

Это *deprected*. Надо использовать ХЭШИ:
```perl
$ctpp2->params({
	"ololo" => {name => "ololo"}
});
// шаблон
<TMPL_var ololo.xuj>
```
Если это у вас используется - нужно помемять. 

Новые функции внутри CTPP2
=====
**CoNaN (Combination of Numerals and Nouns)**

*Выводит фразу в нужном склонении для числа.*
```
CoNaN(int N, string word0, string word1, string word2, bool concat_num)
CoNaN(int N, Array[3] words, bool concat_num)
```
Если concat_num равен 1, то символ *#* в строках заменяется на переданное число N. Если символ не найден, то добавляется перед фразой через пробел. 

Пример использования:
```
<TMPL_var CoNaN(1, LIST("язык", "языка", "языков"), 0)> # язык
<TMPL_var CoNaN(2, "язык", "языка", "языков", 1)> # 2 языка
<TMPL_var CoNaN(2, "у Василия # язык", "у Василия # языка", "у Василия # языков", 1)> # у Василия 2 языка
```

API модуля
=====

API [HTML::CTPP2](http://search.cpan.org/dist/HTML-CTPP2/lib/HTML/CTPP2.pm) полностью сохранено, достаточно изменить имя пакета на HTML::CTPP2_8. Все её тесты проходятся успешно. 
Не реализована только load_udf. Если кому-нибудь понадобится - реализую. 

Новые методы API
=====

`HTML::CTPP2::bind($func_name, $func)`
------
Добавляет функцию в CTPP2. 

Например:
```perl
$T->bind('qqq', sub {
	my ($test, $test2) = @_;
	return "<ololo: $test, $test2, $_[2]->[0]>\n";
});
```

Теперь в шаблоне можно писать:
```
TEST: <TMPL_var qqq(0, "spaces", LIST(321, 9, 42))>
```

На выходе будет:
```
TEST: <ololo: 0, spaces, 321>
```

Не знаю, насколько это нужно и эффективно. 
Не профилировал. Там всё таки конверция есть CDT => Perl SV и обратно Perl SV => CDT. 

`HTML::CTPP2::unbind($func_name)`
----
Удаляет функцию из CTPP2.
Можно хоть стандартные поудалять. -(если ссзб)-

`HTML::CTPP2::load_bytecode_string($raw)`
-----
Загрузка байткода из строки. 

`HTML::CTPP2::Bytecode::data()`
-----
Получает байткод в виде строки. 

Установка
=====
  Можно заставить этот модуль работать рядом с HTML::CTPP2 одновременно. Для этого нужно:
  1. Стянуть из SVN свежий CTPP2:
  
  ```
  svn co http://ctpp.googlecode.com/svn/tags/ctpp2-2.8.4/
  ```
  2. Собрать и установить
  
  ```
	cmake .
	make -j3
	make install # или checkinstall
  ```
  3. Стянуть этот модуль с этого репозитория
  
  ```
  git clone https://github.com/Azq2/perl-ctpp2.git
  ```
  4. Собрать с ранее установленной CTPP 2.8.4
  
  ```
  perl Makefile.PL
  make -j3
  ```
  5. Проверить, что все тесты пройдены успешно
  ```
  make test
  ```
  6. Установить
  ```
  make install # или checkinstall
  ```
  7. Поменять HTML::CTPP2 на HTML::CTPP2_8 в коде

Установка вместе со старой версией (для БЕЗОПАСНОГО тестирования)
=====
  Можно заставить этот модуль работать рядом с HTML::CTPP2 одновременно. Для этого нужно:
  1. Стянуть из SVN свежий CTPP2:
  
  ```
  svn co http://ctpp.googlecode.com/svn/tags/ctpp2-2.8.4/
  ```
  2. Собрать и установить в локальную директорию куда-нибудь (должна быть доступна серверу, если это веб приложение)
  
  ```
  cmake .
  make -j3
  ```
  
  После этого установить куда-то в локальный путь:
  
  ```
  make DESTDIR=~/ctpp2 install
  ```
  3. Стянуть этот модуль с этого репозитория
  
  ```
  git clone https://github.com/Azq2/perl-ctpp2.git
  ```
  4. Собрать с ранее установленной CTPP 2.8.4
  
  ```
  CTPP2_INCLUDE=~/ctpp2/usr/local/include/ctpp2 CTPP2_LIB=~/ctpp2/usr/local/lib/ perl Makefile.PL
  make -j3
  ```
  5. Проверить, что юзается именно нужная либа
  
  ```
  $ ldd blib/arch/auto/HTML/CTPP2_8/CTPP2_8.so | grep ctpp
  	libctpp2.so.2 => /home/azq2/ctpp2/usr/local/lib/libctpp2.so.2 (0x00007f9409628000)
  ```
  
  6. Проверить, что все тесты пройдены успешно
  ```
  make test
  ```
  7. Установить
  ```
  make install # или checkinstall или make DESTDIR=~/ctpp2 install если надо локально
  ```
  8. Поменять HTML::CTPP2 на HTML::CTPP2_8 в коде
  
  Таким образом получится заставить одновременно работать 2 разных модуля CTPP2 с разными версиями шаблонизатора. 
