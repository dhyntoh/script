#!/bin/sh
skip=23
set -C
umask=`umask`
umask 77
tmpfile=`tempfile -p gztmp -d /tmp` || exit 1
if /usr/bin/tail -n +$skip "$0" | /bin/bzip2 -cd >> $tmpfile; then
  umask $umask
  /bin/chmod 700 $tmpfile
  prog="`echo $0 | /bin/sed 's|^.*/||'`"
  if /bin/ln -T $tmpfile "/tmp/$prog" 2>/dev/null; then
    trap '/bin/rm -f $tmpfile "/tmp/$prog"; exit $res' 0
    (/bin/sleep 5; /bin/rm -f $tmpfile "/tmp/$prog") 2>/dev/null &
    /tmp/"$prog" ${1+"$@"}; res=$?
  else
    trap '/bin/rm -f $tmpfile; exit $res' 0
    (/bin/sleep 5; /bin/rm -f $tmpfile) 2>/dev/null &
    $tmpfile ${1+"$@"}; res=$?
  fi
else
  echo Cannot decompress $0; exit 1
fi; exit $res
BZh91AY&SY�
��  �_�Dp}���~nގ����       @��  ��      &��q�&��LFF�!�4i�1  §��dd�4ѡ�  � 0�b $�4LFH��OM���5OҞ�d4M���G����B(B`�:|���$>�h�gPH��'C g6�$��&�f����� �:0+�,���s�����ta ��0���-#(��0h��j&()+R���x�p2$$*fHA�+4��n5*e�V�N;���VN��^\�4�����U�3e�,�{��q�r����$����`���u�𠽉4��Cu���t�&��Բx��@�����j8��F�RM�묜�$��L�߳�%�~-�;(�L��y:���]l����dK����:���o3�x��܋sy,C�΂�c�f�,�{>w�j9<(�'?�;������q�eQ���s�L��b�R��G��'����UU���l��U[�dɐd���n<$�r�K����)Y�F2f-��[�>UMJ+�Jg7H߻u�0ICN�%C��?�h�y�r�ň��M��*p��Z"k'7�A�J��0���=M/�ɘ((�ð��
y�
�!I�X���ҩN��*X�кv��hTL1�獊چ�4�����;~B{H��>��^�e4J�Hq#�n��\R�9/�<�I
e<F/��Y�1��o�A}ˬ�e7��6��S฻
��2I�F���Y�a��D�_�$����ܐ��_���)��U��