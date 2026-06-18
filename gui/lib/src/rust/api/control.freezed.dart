// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'control.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$BridgeError {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BridgeError);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'BridgeError()';
}


}

/// @nodoc
class $BridgeErrorCopyWith<$Res>  {
$BridgeErrorCopyWith(BridgeError _, $Res Function(BridgeError) __);
}


/// Adds pattern-matching-related methods to [BridgeError].
extension BridgeErrorPatterns on BridgeError {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( BridgeError_Unauthorized value)?  unauthorized,TResult Function( BridgeError_UnsupportedVersion value)?  unsupportedVersion,TResult Function( BridgeError_InvalidRequest value)?  invalidRequest,TResult Function( BridgeError_NotConnected value)?  notConnected,TResult Function( BridgeError_Internal value)?  internal,TResult Function( BridgeError_Transport value)?  transport,required TResult orElse(),}){
final _that = this;
switch (_that) {
case BridgeError_Unauthorized() when unauthorized != null:
return unauthorized(_that);case BridgeError_UnsupportedVersion() when unsupportedVersion != null:
return unsupportedVersion(_that);case BridgeError_InvalidRequest() when invalidRequest != null:
return invalidRequest(_that);case BridgeError_NotConnected() when notConnected != null:
return notConnected(_that);case BridgeError_Internal() when internal != null:
return internal(_that);case BridgeError_Transport() when transport != null:
return transport(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( BridgeError_Unauthorized value)  unauthorized,required TResult Function( BridgeError_UnsupportedVersion value)  unsupportedVersion,required TResult Function( BridgeError_InvalidRequest value)  invalidRequest,required TResult Function( BridgeError_NotConnected value)  notConnected,required TResult Function( BridgeError_Internal value)  internal,required TResult Function( BridgeError_Transport value)  transport,}){
final _that = this;
switch (_that) {
case BridgeError_Unauthorized():
return unauthorized(_that);case BridgeError_UnsupportedVersion():
return unsupportedVersion(_that);case BridgeError_InvalidRequest():
return invalidRequest(_that);case BridgeError_NotConnected():
return notConnected(_that);case BridgeError_Internal():
return internal(_that);case BridgeError_Transport():
return transport(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( BridgeError_Unauthorized value)?  unauthorized,TResult? Function( BridgeError_UnsupportedVersion value)?  unsupportedVersion,TResult? Function( BridgeError_InvalidRequest value)?  invalidRequest,TResult? Function( BridgeError_NotConnected value)?  notConnected,TResult? Function( BridgeError_Internal value)?  internal,TResult? Function( BridgeError_Transport value)?  transport,}){
final _that = this;
switch (_that) {
case BridgeError_Unauthorized() when unauthorized != null:
return unauthorized(_that);case BridgeError_UnsupportedVersion() when unsupportedVersion != null:
return unsupportedVersion(_that);case BridgeError_InvalidRequest() when invalidRequest != null:
return invalidRequest(_that);case BridgeError_NotConnected() when notConnected != null:
return notConnected(_that);case BridgeError_Internal() when internal != null:
return internal(_that);case BridgeError_Transport() when transport != null:
return transport(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function()?  unauthorized,TResult Function()?  unsupportedVersion,TResult Function()?  invalidRequest,TResult Function()?  notConnected,TResult Function( String message)?  internal,TResult Function( String message)?  transport,required TResult orElse(),}) {final _that = this;
switch (_that) {
case BridgeError_Unauthorized() when unauthorized != null:
return unauthorized();case BridgeError_UnsupportedVersion() when unsupportedVersion != null:
return unsupportedVersion();case BridgeError_InvalidRequest() when invalidRequest != null:
return invalidRequest();case BridgeError_NotConnected() when notConnected != null:
return notConnected();case BridgeError_Internal() when internal != null:
return internal(_that.message);case BridgeError_Transport() when transport != null:
return transport(_that.message);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function()  unauthorized,required TResult Function()  unsupportedVersion,required TResult Function()  invalidRequest,required TResult Function()  notConnected,required TResult Function( String message)  internal,required TResult Function( String message)  transport,}) {final _that = this;
switch (_that) {
case BridgeError_Unauthorized():
return unauthorized();case BridgeError_UnsupportedVersion():
return unsupportedVersion();case BridgeError_InvalidRequest():
return invalidRequest();case BridgeError_NotConnected():
return notConnected();case BridgeError_Internal():
return internal(_that.message);case BridgeError_Transport():
return transport(_that.message);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function()?  unauthorized,TResult? Function()?  unsupportedVersion,TResult? Function()?  invalidRequest,TResult? Function()?  notConnected,TResult? Function( String message)?  internal,TResult? Function( String message)?  transport,}) {final _that = this;
switch (_that) {
case BridgeError_Unauthorized() when unauthorized != null:
return unauthorized();case BridgeError_UnsupportedVersion() when unsupportedVersion != null:
return unsupportedVersion();case BridgeError_InvalidRequest() when invalidRequest != null:
return invalidRequest();case BridgeError_NotConnected() when notConnected != null:
return notConnected();case BridgeError_Internal() when internal != null:
return internal(_that.message);case BridgeError_Transport() when transport != null:
return transport(_that.message);case _:
  return null;

}
}

}

/// @nodoc


class BridgeError_Unauthorized extends BridgeError {
  const BridgeError_Unauthorized(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BridgeError_Unauthorized);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'BridgeError.unauthorized()';
}


}




/// @nodoc


class BridgeError_UnsupportedVersion extends BridgeError {
  const BridgeError_UnsupportedVersion(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BridgeError_UnsupportedVersion);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'BridgeError.unsupportedVersion()';
}


}




/// @nodoc


class BridgeError_InvalidRequest extends BridgeError {
  const BridgeError_InvalidRequest(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BridgeError_InvalidRequest);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'BridgeError.invalidRequest()';
}


}




/// @nodoc


class BridgeError_NotConnected extends BridgeError {
  const BridgeError_NotConnected(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BridgeError_NotConnected);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'BridgeError.notConnected()';
}


}




/// @nodoc


class BridgeError_Internal extends BridgeError {
  const BridgeError_Internal({required this.message}): super._();
  

 final  String message;

/// Create a copy of BridgeError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BridgeError_InternalCopyWith<BridgeError_Internal> get copyWith => _$BridgeError_InternalCopyWithImpl<BridgeError_Internal>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BridgeError_Internal&&(identical(other.message, message) || other.message == message));
}


@override
int get hashCode => Object.hash(runtimeType,message);

@override
String toString() {
  return 'BridgeError.internal(message: $message)';
}


}

/// @nodoc
abstract mixin class $BridgeError_InternalCopyWith<$Res> implements $BridgeErrorCopyWith<$Res> {
  factory $BridgeError_InternalCopyWith(BridgeError_Internal value, $Res Function(BridgeError_Internal) _then) = _$BridgeError_InternalCopyWithImpl;
@useResult
$Res call({
 String message
});




}
/// @nodoc
class _$BridgeError_InternalCopyWithImpl<$Res>
    implements $BridgeError_InternalCopyWith<$Res> {
  _$BridgeError_InternalCopyWithImpl(this._self, this._then);

  final BridgeError_Internal _self;
  final $Res Function(BridgeError_Internal) _then;

/// Create a copy of BridgeError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? message = null,}) {
  return _then(BridgeError_Internal(
message: null == message ? _self.message : message // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class BridgeError_Transport extends BridgeError {
  const BridgeError_Transport({required this.message}): super._();
  

 final  String message;

/// Create a copy of BridgeError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BridgeError_TransportCopyWith<BridgeError_Transport> get copyWith => _$BridgeError_TransportCopyWithImpl<BridgeError_Transport>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BridgeError_Transport&&(identical(other.message, message) || other.message == message));
}


@override
int get hashCode => Object.hash(runtimeType,message);

@override
String toString() {
  return 'BridgeError.transport(message: $message)';
}


}

/// @nodoc
abstract mixin class $BridgeError_TransportCopyWith<$Res> implements $BridgeErrorCopyWith<$Res> {
  factory $BridgeError_TransportCopyWith(BridgeError_Transport value, $Res Function(BridgeError_Transport) _then) = _$BridgeError_TransportCopyWithImpl;
@useResult
$Res call({
 String message
});




}
/// @nodoc
class _$BridgeError_TransportCopyWithImpl<$Res>
    implements $BridgeError_TransportCopyWith<$Res> {
  _$BridgeError_TransportCopyWithImpl(this._self, this._then);

  final BridgeError_Transport _self;
  final $Res Function(BridgeError_Transport) _then;

/// Create a copy of BridgeError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? message = null,}) {
  return _then(BridgeError_Transport(
message: null == message ? _self.message : message // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

// dart format on
